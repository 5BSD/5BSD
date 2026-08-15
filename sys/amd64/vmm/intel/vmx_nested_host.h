/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_HOST_H_
#define	_VMM_INTEL_VMX_NESTED_HOST_H_

#include "vmx_nested_types.h"

struct vmx_nested_capabilities;

struct vmx_nested_host_state {
	uint64_t cr0;
	uint64_t cr3;
	uint64_t cr4;
	uint64_t fs_base;
	uint64_t gs_base;
	uint64_t tr_base;
	uint64_t gdtr_base;
	uint64_t idtr_base;
	uint32_t sysenter_cs;
	uint64_t sysenter_esp;
	uint64_t sysenter_eip;
	uint64_t rsp;
	uint64_t rip;
	uint64_t pat;
	uint64_t efer;
	uint16_t es_selector;
	uint16_t cs_selector;
	uint16_t ss_selector;
	uint16_t ds_selector;
	uint16_t fs_selector;
	uint16_t gs_selector;
	uint16_t tr_selector;
	bool root_ia32e;
};

enum vmx_nested_host_failure {
	VMX_NESTED_HOST_OK = 0,
	VMX_NESTED_HOST_CR0,
	VMX_NESTED_HOST_CR3,
	VMX_NESTED_HOST_CR4,
	VMX_NESTED_HOST_SYSENTER,
	VMX_NESTED_HOST_PAT,
	VMX_NESTED_HOST_EFER,
	VMX_NESTED_HOST_SELECTOR,
	VMX_NESTED_HOST_BASE,
	VMX_NESTED_HOST_ADDRESS_SPACE,
};

int	vmx_nested_host_state_validate(
	    const struct vmx_nested_capabilities *, uint32_t, uint32_t,
	    const struct vmx_nested_host_state *,
	    enum vmx_nested_host_failure *);

#endif /* _VMM_INTEL_VMX_NESTED_HOST_H_ */
