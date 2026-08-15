/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_EXECUTION_H_
#define	_VMM_INTEL_VMX_NESTED_EXECUTION_H_

#include "vmx_nested_types.h"

#include "vmx_nested_entry.h"

struct vmx_nested_execution_compose_input {
	const struct vmx_nested_execution_state *l0;
	const struct vmx_nested_execution_state *l1;
	uint32_t	l0_cr3_target_count;
	uint32_t	l1_cr3_target_count;
	bool		l0_cr3_load_exiting;
	bool		l1_cr3_load_exiting;
	bool		l0_ple_enabled;
	bool		l1_ple_enabled;
};

struct vmx_nested_execution_plan {
	struct vmx_nested_execution_state state;
	/*
	 * Preserve the two original policies for exit routing and nested-exit
	 * state reconstruction.  The effective hardware fields alone cannot
	 * identify which level requested an exit.
	 */
	struct vmx_nested_execution_state l0;
	struct vmx_nested_execution_state l1;
	uint32_t	l0_cr3_target_count;
	uint32_t	l1_cr3_target_count;
	uint32_t	cr3_target_count;
	bool		l0_cr3_load_exiting;
	bool		l1_cr3_load_exiting;
	bool		l0_ple_enabled;
	bool		l1_ple_enabled;
	/*
	 * True when differing L0/L1 page-fault filters require VMCS02 to
	 * exit on every page fault and route the condition in software.
	 */
	bool		page_fault_software_filter;
};

int	vmx_nested_execution_compose(
	    const struct vmx_nested_execution_compose_input *,
	    struct vmx_nested_execution_plan *);

#endif /* _VMM_INTEL_VMX_NESTED_EXECUTION_H_ */
