/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/errno.h>
#include <sys/param.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <stdint.h>
#else
#include <sys/systm.h>
#endif

#include "vmx_nested_caps.h"
#include "vmx_nested_continuation.h"
#include "vmx_nested_entry_runtime.h"
#include "vmx_nested_msr_workspace.h"
#include "vmx_nested_restore_transaction.h"
#include "vmx_nested_state_range.h"
#include "vmx_nested_vmcs_registry.h"

int
vmx_nested_restore_destination_validate(
    const struct vmx_nested_l0_continuation *continuation,
    const struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_msr_workspace *workspace, bool plan_valid,
    bool portable_valid)
{
	int error;

	if (continuation == NULL || runtime == NULL || workspace == NULL)
		return (EINVAL);
	error = vmx_nested_l0_continuation_validate(continuation);
	if (error != 0)
		return (error);
	error = vmx_nested_entry_runtime_validate(runtime);
	if (error != 0)
		return (error);
	error = vmx_nested_msr_workspace_validate(workspace);
	if (error != 0)
		return (error);
	if (continuation->state != VMX_NESTED_L0_CONTINUATION_IDLE ||
	    runtime->state != VMX_NESTED_ENTRY_RUNTIME_IDLE ||
	    workspace->active || plan_valid || portable_valid)
		return (EBUSY);
	return (0);
}

static int
nvmxrt_validate(struct vmx_nested_vmcs_registry *destination,
    struct vmx_nested_vmcs_registry *replacement,
    struct vmx_nested_restore_workspace *workspaces, size_t count)
{
	size_t binding_bytes, entry_bytes, other_entry_bytes;
	uint32_t required_capacity;
	int error;

	if (destination == NULL || replacement == NULL ||
	    destination == replacement || !destination->initialized ||
	    !replacement->initialized ||
	    destination->limit != replacement->limit ||
	    !vmx_nested_capabilities_equal(&destination->capabilities,
	    &replacement->capabilities) ||
	    (count != 0 && workspaces == NULL))
		return (EINVAL);
	if (count > (size_t)-1 / sizeof(*workspaces))
		return (EOVERFLOW);
	binding_bytes = count * sizeof(*workspaces);
	/*
	 * Registry replacement rewrites both registry headers and list-link
	 * storage.  Validate the complete binding table before acquiring any
	 * workspace so publication cannot overwrite the rollback traversal.
	 * The overlap helper also rejects malformed registry shape and count.
	 */
	if (vmx_nested_vmcs_registry_storage_overlaps(destination, workspaces,
	    binding_bytes) ||
	    vmx_nested_vmcs_registry_storage_overlaps(replacement, workspaces,
	    binding_bytes))
		return (EINVAL);
	for (size_t i = 0; i < count; i++) {
		if (!workspaces[i].active)
			continue;
		if (workspaces[i].workspace == NULL ||
		    workspaces[i].capabilities == NULL)
			return (EINVAL);
		/*
		 * generation is dereferenced below and is later used as the durable
		 * ownership token for rollback.  Validate its natural alignment before
		 * either operation; otherwise two differently valued, partially
		 * overlapping outputs can evade the equality check below and one begin
		 * can corrupt the other vCPU's token.
		 */
		if (workspaces[i].generation == NULL ||
		    ((uintptr_t)workspaces[i].generation %
		    _Alignof(uint64_t)) != 0)
			return (EINVAL);
		error = vmx_nested_msr_workspace_capacity(
		    workspaces[i].capabilities, &required_capacity);
		if (error != 0 ||
		    !vmx_nested_capabilities_equal(
		    workspaces[i].capabilities,
		    &destination->capabilities) ||
		    *workspaces[i].generation != 0 ||
		    workspaces[i].workspace->plan == NULL ||
		    workspaces[i].workspace->rollback == NULL ||
		    workspaces[i].workspace->capacity == 0 ||
		    vmx_nested_msr_workspace_validate(
		    workspaces[i].workspace) != 0 ||
		    workspaces[i].workspace->capacity != required_capacity ||
		    workspaces[i].workspace->active)
			return (EINVAL);
	}
	for (size_t i = 0; i < count; i++) {
		if (!workspaces[i].active)
			continue;
		entry_bytes = (size_t)workspaces[i].workspace->capacity *
		    sizeof(*workspaces[i].workspace->plan);
		/*
		 * Scratch survives the publication transaction and is mutated by
		 * later nested entry and exit processing.  It therefore cannot be
		 * carved out of any object whose identity or contents the
		 * transaction publishes or continues to use.  Checking only
		 * cross-vCPU scratch aliases would permit a successful restore
		 * followed by delayed registry or binding-table corruption.
		 */
		if (vmx_nested_vmcs_registry_storage_overlaps(destination,
		    workspaces[i].workspace, sizeof(*workspaces[i].workspace)) ||
		    vmx_nested_vmcs_registry_storage_overlaps(destination,
		    workspaces[i].capabilities,
		    sizeof(*workspaces[i].capabilities)) ||
		    vmx_nested_vmcs_registry_storage_overlaps(replacement,
		    workspaces[i].workspace, sizeof(*workspaces[i].workspace)) ||
		    vmx_nested_vmcs_registry_storage_overlaps(replacement,
		    workspaces[i].capabilities,
		    sizeof(*workspaces[i].capabilities)) ||
		    vmx_nested_state_ranges_overlap(workspaces, binding_bytes,
		    workspaces[i].workspace, sizeof(*workspaces[i].workspace)) ||
		    vmx_nested_state_ranges_overlap(workspaces, binding_bytes,
		    workspaces[i].capabilities,
		    sizeof(*workspaces[i].capabilities)) ||
		    vmx_nested_vmcs_registry_storage_overlaps(destination,
		    workspaces[i].workspace->plan, entry_bytes) ||
		    vmx_nested_vmcs_registry_storage_overlaps(destination,
		    workspaces[i].workspace->rollback, entry_bytes) ||
		    vmx_nested_vmcs_registry_storage_overlaps(replacement,
		    workspaces[i].workspace->plan, entry_bytes) ||
		    vmx_nested_vmcs_registry_storage_overlaps(replacement,
		    workspaces[i].workspace->rollback, entry_bytes) ||
		    vmx_nested_state_ranges_overlap(workspaces[i].workspace->plan, entry_bytes,
		    workspaces, binding_bytes) ||
		    vmx_nested_state_ranges_overlap(workspaces[i].workspace->rollback,
		    entry_bytes, workspaces, binding_bytes))
			return (EINVAL);
		/*
		 * The generation is an output.  Do not let it overwrite any
		 * transaction input, registry bookkeeping, workspace owner, or
		 * workspace storage while begin/rollback is still using it.
		 */
		if (vmx_nested_vmcs_registry_storage_overlaps(destination,
		    workspaces[i].generation, sizeof(*workspaces[i].generation)) ||
		    vmx_nested_vmcs_registry_storage_overlaps(replacement,
		    workspaces[i].generation, sizeof(*workspaces[i].generation)) ||
		    vmx_nested_state_ranges_overlap(workspaces[i].generation,
		    sizeof(*workspaces[i].generation), workspaces,
		    binding_bytes))
			return (EINVAL);
		for (size_t j = 0; j < i; j++) {
			if (!workspaces[j].active)
				continue;
			if (vmx_nested_state_ranges_overlap(
			    workspaces[i].workspace,
			    sizeof(*workspaces[i].workspace),
			    workspaces[j].workspace,
			    sizeof(*workspaces[j].workspace)) ||
			    vmx_nested_state_ranges_overlap(
			    workspaces[i].workspace,
			    sizeof(*workspaces[i].workspace),
			    workspaces[j].capabilities,
			    sizeof(*workspaces[j].capabilities)) ||
			    vmx_nested_state_ranges_overlap(
			    workspaces[i].capabilities,
			    sizeof(*workspaces[i].capabilities),
			    workspaces[j].workspace,
			    sizeof(*workspaces[j].workspace)) ||
			    vmx_nested_state_ranges_overlap(
			    workspaces[i].generation,
			    sizeof(*workspaces[i].generation),
			    workspaces[j].generation,
			    sizeof(*workspaces[j].generation)))
				return (EINVAL);
			/*
			 * Plan and rollback arrays are destination-local mutable
			 * scratch.  Two otherwise distinct vCPU workspaces must not
			 * share any portion of them: both acquisitions can succeed,
			 * but the first nested entry or exit would then overwrite
			 * the other vCPU's transaction state.
			 */
			entry_bytes = (size_t)
			    workspaces[i].workspace->capacity *
			    sizeof(*workspaces[i].workspace->plan);
			other_entry_bytes = (size_t)
			    workspaces[j].workspace->capacity *
			    sizeof(*workspaces[j].workspace->plan);
			if (vmx_nested_state_ranges_overlap(workspaces[i].workspace->plan,
			    entry_bytes, workspaces[j].workspace->plan,
			    other_entry_bytes) ||
			    vmx_nested_state_ranges_overlap(workspaces[i].workspace->plan,
			    entry_bytes, workspaces[j].workspace->rollback,
			    other_entry_bytes) ||
			    vmx_nested_state_ranges_overlap(workspaces[i].workspace->rollback,
			    entry_bytes, workspaces[j].workspace->plan,
			    other_entry_bytes) ||
			    vmx_nested_state_ranges_overlap(workspaces[i].workspace->rollback,
			    entry_bytes, workspaces[j].workspace->rollback,
			    other_entry_bytes))
				return (EINVAL);
		}
		for (size_t j = 0; j < count; j++) {
			if (!workspaces[j].active)
				continue;
			entry_bytes = (size_t)
			    workspaces[j].workspace->capacity *
			    sizeof(*workspaces[j].workspace->plan);
			if (vmx_nested_state_ranges_overlap(workspaces[i].workspace->plan,
			    (size_t)workspaces[i].workspace->capacity *
			    sizeof(*workspaces[i].workspace->plan),
			    workspaces[j].workspace,
			    sizeof(*workspaces[j].workspace)) ||
			    vmx_nested_state_ranges_overlap(workspaces[i].workspace->rollback,
			    (size_t)workspaces[i].workspace->capacity *
			    sizeof(*workspaces[i].workspace->rollback),
			    workspaces[j].workspace,
			    sizeof(*workspaces[j].workspace)) ||
			    vmx_nested_state_ranges_overlap(workspaces[i].workspace->plan,
			    (size_t)workspaces[i].workspace->capacity *
			    sizeof(*workspaces[i].workspace->plan),
			    workspaces[j].capabilities,
			    sizeof(*workspaces[j].capabilities)) ||
			    vmx_nested_state_ranges_overlap(workspaces[i].workspace->rollback,
			    (size_t)workspaces[i].workspace->capacity *
			    sizeof(*workspaces[i].workspace->rollback),
			    workspaces[j].capabilities,
			    sizeof(*workspaces[j].capabilities)) ||
			    vmx_nested_state_ranges_overlap(workspaces[i].workspace->plan,
			    (size_t)workspaces[i].workspace->capacity *
			    sizeof(*workspaces[i].workspace->plan),
			    workspaces[j].generation,
			    sizeof(*workspaces[j].generation)) ||
			    vmx_nested_state_ranges_overlap(workspaces[i].workspace->rollback,
			    (size_t)workspaces[i].workspace->capacity *
			    sizeof(*workspaces[i].workspace->rollback),
			    workspaces[j].generation,
			    sizeof(*workspaces[j].generation)) ||
			    vmx_nested_state_ranges_overlap(workspaces[i].generation,
			    sizeof(*workspaces[i].generation),
			    workspaces[j].workspace,
			    sizeof(*workspaces[j].workspace)) ||
			    vmx_nested_state_ranges_overlap(workspaces[i].generation,
			    sizeof(*workspaces[i].generation),
			    workspaces[j].capabilities,
			    sizeof(*workspaces[j].capabilities)) ||
			    vmx_nested_state_ranges_overlap(workspaces[i].generation,
			    sizeof(*workspaces[i].generation),
			    workspaces[j].workspace->plan, entry_bytes) ||
			    vmx_nested_state_ranges_overlap(workspaces[i].generation,
			    sizeof(*workspaces[i].generation),
			    workspaces[j].workspace->rollback, entry_bytes))
				return (EINVAL);
		}
	}
	return (0);
}

int
vmx_nested_restore_transaction_commit(
    struct vmx_nested_vmcs_registry *destination,
    struct vmx_nested_vmcs_registry *replacement,
    struct vmx_nested_restore_workspace *workspaces, size_t count)
{
	size_t begun;
	bool rollback_failed;
	int end_error, error;

	error = nvmxrt_validate(destination, replacement, workspaces, count);
	if (error != 0)
		return (error);
	begun = 0;
	rollback_failed = false;
	for (size_t i = 0; i < count; i++) {
		if (!workspaces[i].active)
			continue;
		error = vmx_nested_msr_workspace_begin(
		    workspaces[i].workspace, workspaces[i].capabilities,
		    workspaces[i].entry_load_count,
		    workspaces[i].exit_store_count,
		    workspaces[i].exit_load_count,
		    workspaces[i].generation);
		if (error != 0)
			goto rollback;
		begun = i + 1;
	}
	error = vmx_nested_vmcs_registry_replace(destination, replacement);
	if (error == 0)
		return (0);

rollback:
	while (begun != 0) {
		begun--;
		if (!workspaces[begun].active ||
		    *workspaces[begun].generation == 0)
			continue;
		end_error = vmx_nested_msr_workspace_end(
		    workspaces[begun].workspace,
		    *workspaces[begun].generation);
		if (end_error != 0) {
			/* Preserve the generation which still names the owner. */
			rollback_failed = true;
			error = EIO;
			continue;
		}
		*workspaces[begun].generation = 0;
	}
#ifdef _KERNEL
	if (rollback_failed)
		panic("%s: validated nested restore rollback failed", __func__);
#else
	(void)rollback_failed;
#endif
	return (error);
}
