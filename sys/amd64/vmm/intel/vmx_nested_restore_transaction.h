/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_RESTORE_TRANSACTION_H_
#define	_VMM_INTEL_VMX_NESTED_RESTORE_TRANSACTION_H_

#include "vmx_nested_types.h"

struct vmx_nested_capabilities;
struct vmx_nested_entry_runtime;
struct vmx_nested_l0_continuation;
struct vmx_nested_msr_workspace;
struct vmx_nested_vmcs_registry;

/*
 * Destination-local scratch storage is acquired before the restored VMCS
 * registry becomes visible.  A failed transaction leaves the destination
 * registry unchanged and every listed workspace inactive.  Each generation
 * output must be distinct and disjoint from the registries, binding array,
 * capability records, workspace owners, and workspace storage.  The binding
 * array, capability records, and workspace owners must likewise be disjoint
 * from both registries and from every mutable owner.  Mutable plan and
 * rollback storage must also be disjoint across active vCPU workspaces.
 */
struct vmx_nested_restore_workspace {
	struct vmx_nested_msr_workspace *workspace;
	const struct vmx_nested_capabilities *capabilities;
	uint64_t *generation;
	uint32_t entry_load_count;
	uint32_t exit_store_count;
	uint32_t exit_load_count;
	bool active;
};

/*
 * VM-wide restore publishes a replacement registry before copying staged
 * per-vCPU state.  Every destination vCPU must therefore be free of an older
 * cold or prepared L2 transaction, even when the incoming vCPU is inactive.
 * Otherwise an inactive source could inherit destination-only runtime state
 * that refers to the registry being replaced.
 */
int	vmx_nested_restore_destination_validate(
	    const struct vmx_nested_l0_continuation *,
	    const struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_msr_workspace *, bool, bool);
int	vmx_nested_restore_transaction_commit(
	    struct vmx_nested_vmcs_registry *,
	    struct vmx_nested_vmcs_registry *,
	    struct vmx_nested_restore_workspace *, size_t);

#endif /* _VMM_INTEL_VMX_NESTED_RESTORE_TRANSACTION_H_ */
