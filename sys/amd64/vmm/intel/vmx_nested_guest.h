/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_GUEST_H_
#define	_VMM_INTEL_VMX_NESTED_GUEST_H_

#include "vmx_nested_types.h"

struct vmx_nested_capabilities;

struct vmx_nested_guest_control_state {
	uint64_t cr0;
	uint64_t cr3;
	uint64_t cr4;
	uint64_t dr7;
	uint32_t sysenter_cs;
	uint64_t sysenter_esp;
	uint64_t sysenter_eip;
	uint64_t pat;
	uint64_t efer;
};

static __inline bool
vmx_nested_guest_control_state_equal(
    const struct vmx_nested_guest_control_state *a,
    const struct vmx_nested_guest_control_state *b)
{

	return (a != NULL && b != NULL && a->cr0 == b->cr0 &&
	    a->cr3 == b->cr3 && a->cr4 == b->cr4 && a->dr7 == b->dr7 &&
	    a->sysenter_cs == b->sysenter_cs &&
	    a->sysenter_esp == b->sysenter_esp &&
	    a->sysenter_eip == b->sysenter_eip && a->pat == b->pat &&
	    a->efer == b->efer);
}

enum vmx_nested_guest_segment_id {
	VMX_NESTED_GUEST_ES = 0,
	VMX_NESTED_GUEST_CS,
	VMX_NESTED_GUEST_SS,
	VMX_NESTED_GUEST_DS,
	VMX_NESTED_GUEST_FS,
	VMX_NESTED_GUEST_GS,
	VMX_NESTED_GUEST_TR,
	VMX_NESTED_GUEST_LDTR,
	VMX_NESTED_GUEST_SEGMENT_COUNT,
};

struct vmx_nested_guest_segment {
	uint16_t selector;
	uint32_t limit;
	uint32_t access;
	uint64_t base;
};

struct vmx_nested_guest_arch_state {
	struct vmx_nested_guest_segment segment[
	    VMX_NESTED_GUEST_SEGMENT_COUNT];
	uint32_t gdtr_limit;
	uint32_t idtr_limit;
	uint64_t gdtr_base;
	uint64_t idtr_base;
	uint64_t rsp;
	uint64_t rip;
	uint64_t rflags;
	uint64_t pending_debug;
	uint64_t debugctl;
	uint32_t activity;
	uint32_t interruptibility;
	bool in_smm;
};

static __inline bool
vmx_nested_guest_arch_state_equal(
    const struct vmx_nested_guest_arch_state *a,
    const struct vmx_nested_guest_arch_state *b)
{
	unsigned int i;

	if (a == NULL || b == NULL)
		return (false);
	for (i = 0; i < VMX_NESTED_GUEST_SEGMENT_COUNT; i++) {
		if (a->segment[i].selector != b->segment[i].selector ||
		    a->segment[i].limit != b->segment[i].limit ||
		    a->segment[i].access != b->segment[i].access ||
		    a->segment[i].base != b->segment[i].base)
			return (false);
	}
	return (a->gdtr_limit == b->gdtr_limit &&
	    a->idtr_limit == b->idtr_limit &&
	    a->gdtr_base == b->gdtr_base && a->idtr_base == b->idtr_base &&
	    a->rsp == b->rsp && a->rip == b->rip &&
	    a->rflags == b->rflags &&
	    a->pending_debug == b->pending_debug &&
	    a->debugctl == b->debugctl && a->activity == b->activity &&
	    a->interruptibility == b->interruptibility &&
	    a->in_smm == b->in_smm);
}

enum vmx_nested_guest_control_failure {
	VMX_NESTED_GUEST_CONTROL_OK = 0,
	VMX_NESTED_GUEST_CR0,
	VMX_NESTED_GUEST_CR3,
	VMX_NESTED_GUEST_CR4,
	VMX_NESTED_GUEST_DEBUG,
	VMX_NESTED_GUEST_SYSENTER,
	VMX_NESTED_GUEST_PAT,
	VMX_NESTED_GUEST_EFER,
	VMX_NESTED_GUEST_ADDRESS_SPACE,
};

enum vmx_nested_guest_arch_failure {
	VMX_NESTED_GUEST_ARCH_OK = 0,
	VMX_NESTED_GUEST_ARCH_PREREQUISITE,
	VMX_NESTED_GUEST_SEGMENT_SELECTOR,
	VMX_NESTED_GUEST_SEGMENT_BASE,
	VMX_NESTED_GUEST_SEGMENT_LIMIT,
	VMX_NESTED_GUEST_SEGMENT_ACCESS,
	VMX_NESTED_GUEST_DESCRIPTOR_TABLE,
	VMX_NESTED_GUEST_RIP,
	VMX_NESTED_GUEST_RFLAGS,
	VMX_NESTED_GUEST_ACTIVITY,
	VMX_NESTED_GUEST_INTERRUPTIBILITY,
	VMX_NESTED_GUEST_PENDING_DEBUG,
	VMX_NESTED_GUEST_DEBUGCTL,
};

/*
 * These failures occur during guest-state checking after control and host
 * state validation.  They are not VMfailValid instruction error 7 or 8.
 */
int	vmx_nested_guest_control_state_validate(
	    const struct vmx_nested_capabilities *, uint32_t, uint32_t,
	    uint32_t, const struct vmx_nested_guest_control_state *,
	    enum vmx_nested_guest_control_failure *);
int	vmx_nested_guest_arch_state_validate(
	    const struct vmx_nested_capabilities *, uint32_t, uint32_t,
	    uint32_t, uint32_t, uint32_t,
	    const struct vmx_nested_guest_control_state *,
	    const struct vmx_nested_guest_arch_state *,
	    enum vmx_nested_guest_arch_failure *);

#endif /* _VMM_INTEL_VMX_NESTED_GUEST_H_ */
