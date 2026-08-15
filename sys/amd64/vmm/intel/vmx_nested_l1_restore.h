/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_L1_RESTORE_H_
#define	_VMM_INTEL_VMX_NESTED_L1_RESTORE_H_

#include "vmx_nested_types.h"

#include "vmx_nested_vmcs02.h"
#include "vmx_nested_vmexit.h"
#include "vmx_nested_vmentry.h"

/*
 * One frozen-vCPU transaction spanning the effective L1 processor state and
 * the owned software VMCS12.  begin() must capture rollback state for both
 * objects.  commit_vmcs12() stages the architectural failed-entry fields;
 * commit() is the sole publication point.  abort() must restore every change
 * made after a successful begin().  The transaction snapshots the complete
 * table before begin(); callbacks cannot retain arguments or redirect later
 * apply, commit, finish, or abort operations by mutating the caller's table.
 */
struct vmx_nested_l1_restore_ops {
	int	(*begin)(void *, const struct vmx_nested_vmcs02_id *);
	int	(*apply_l1)(void *,
		    const struct vmx_nested_failed_entry_state_plan *);
	int	(*commit_vmcs12)(void *,
		    const struct vmx_nested_vmcs02_id *,
		    const struct vmx_nested_vmentry_result *);
	int	(*commit)(void *);
	void	(*abort)(void *);
};

struct vmx_nested_l1_restore_result {
	struct vmx_nested_vmcs02_id	id;
	uint32_t	steps_completed;
	bool		committed;
};

/*
 * Ordinary nested VM exit uses a staged VMCS12 image.  All fallible work
 * precedes publish_vmcs12(); finish() only releases transaction ownership and
 * therefore cannot fail.  abort() restores L1 processor state and discards
 * the unpublished staging image.  This table is likewise captured before
 * begin() so rollback identity is immutable for the transaction.
 */
struct vmx_nested_l1_exit_ops {
	int	(*begin)(void *, const struct vmx_nested_vmcs02_id *);
	int	(*stage_vmcs12)(void *,
		    const struct vmx_nested_vmcs02_id *);
	int	(*apply_l1)(void *,
		    const struct vmx_nested_vmexit_state_plan *);
	int	(*publish_vmcs12)(void *,
		    const struct vmx_nested_vmcs02_id *);
	void	(*finish)(void *);
	void	(*abort)(void *);
};

struct vmx_nested_l1_exit_result {
	struct vmx_nested_vmcs02_id	id;
	uint32_t	steps_completed;
	bool		committed;
};

int	vmx_nested_l1_restore_failed_entry(
	    const struct vmx_nested_vmcs02_id *,
	    const struct vmx_nested_failed_entry_state_plan *,
	    const struct vmx_nested_vmentry_result *,
	    const struct vmx_nested_l1_restore_ops *, void *,
	    struct vmx_nested_l1_restore_result *);
int	vmx_nested_l1_restore_vmexit(
	    const struct vmx_nested_vmcs02_id *,
	    const struct vmx_nested_vmexit_state_plan *,
	    const struct vmx_nested_l1_exit_ops *, void *,
	    struct vmx_nested_l1_exit_result *);

#endif /* _VMM_INTEL_VMX_NESTED_L1_RESTORE_H_ */
