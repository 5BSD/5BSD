/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/errno.h>
#ifdef _KERNEL
#include <sys/systm.h>
#endif
#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#endif

#include "vmx_nested_caps.h"
#include "vmx_nested_msr_workspace.h"
#include "vmx_nested_state_range.h"

static bool
nvmx_msr_workspace_overlap(const struct vmx_nested_msr_entry *left,
    const struct vmx_nested_msr_entry *right, uint32_t capacity)
{
	size_t bytes;

	bytes = (size_t)capacity * sizeof(*left);
	if (((uintptr_t)left % _Alignof(struct vmx_nested_msr_entry)) != 0 ||
	    ((uintptr_t)right % _Alignof(struct vmx_nested_msr_entry)) != 0)
		return (true);
	return (vmx_nested_state_ranges_overlap(left, bytes, right, bytes));
}

int
vmx_nested_msr_workspace_capacity(
    const struct vmx_nested_capabilities *capabilities, uint32_t *capacity)
{
	uint32_t candidate;

	if (capacity == NULL ||
	    vmx_nested_capabilities_validate(capabilities) != 0)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(capacity, sizeof(*capacity),
	    capabilities, sizeof(*capabilities)))
		return (EINVAL);
	candidate = 512U * (1U + (uint32_t)((capabilities->misc >> 25) & 7));
	/*
	 * IA32_VMX_MISC represents one through eight groups of 512 entries.
	 * Keep the arithmetic explicit so a future capability extension cannot
	 * silently wrap an allocator size.
	 */
	if (candidate < 512 || candidate > 4096)
		return (EOVERFLOW);
	*capacity = candidate;
	return (0);
}

void
vmx_nested_msr_workspace_init(struct vmx_nested_msr_workspace *workspace)
{

	if (workspace != NULL)
		memset(workspace, 0, sizeof(*workspace));
}

int
vmx_nested_msr_workspace_bind(struct vmx_nested_msr_workspace *workspace,
    const struct vmx_nested_capabilities *capabilities,
    struct vmx_nested_msr_entry *plan,
    struct vmx_nested_msr_entry *rollback, uint32_t capacity)
{
	uint64_t signature;
	size_t bytes;
	uint32_t required;
	int error;

	if (workspace == NULL || capabilities == NULL || plan == NULL ||
	    rollback == NULL)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(workspace, sizeof(*workspace),
	    capabilities, sizeof(*capabilities)))
		return (EINVAL);
	if (workspace->active || workspace->plan != NULL ||
	    workspace->rollback != NULL)
		return (EINVAL);
	error = vmx_nested_msr_workspace_capacity(capabilities, &required);
	if (error != 0)
		return (error);
	if (capacity < required)
		return (ENOSPC);
	/*
	 * Only the architectural maximum is usable.  Ignoring excess caller
	 * storage keeps pointer-range validation and later count checks tied
	 * to the immutable virtual capability contract.
	 */
	capacity = required;
	bytes = (size_t)capacity * sizeof(*plan);
	if (vmx_nested_state_ranges_overlap(workspace, sizeof(*workspace), plan,
	    bytes) ||
	    vmx_nested_state_ranges_overlap(workspace, sizeof(*workspace),
	    rollback, bytes) ||
	    vmx_nested_state_ranges_overlap(capabilities, sizeof(*capabilities),
	    plan, bytes) ||
	    vmx_nested_state_ranges_overlap(capabilities, sizeof(*capabilities),
	    rollback, bytes))
		return (EINVAL);
	if (nvmx_msr_workspace_overlap(plan, rollback, capacity))
		return (EINVAL);
	error = vmx_nested_capabilities_signature(capabilities, &signature);
	if (error != 0)
		return (error);
	workspace->plan = plan;
	workspace->rollback = rollback;
	workspace->capability_signature = signature;
	workspace->capacity = capacity;
	workspace->generation = 0;
	workspace->active = false;
	return (0);
}

int
vmx_nested_msr_workspace_begin(struct vmx_nested_msr_workspace *workspace,
    const struct vmx_nested_capabilities *capabilities,
    uint32_t entry_load_count, uint32_t exit_store_count,
    uint32_t exit_load_count, uint64_t *generation)
{
	uint64_t signature, candidate;
	size_t bytes;
	uint32_t required;
	int error;

	if (workspace == NULL || generation == NULL)
		return (EINVAL);
	if (capabilities == NULL ||
	    vmx_nested_state_ranges_overlap(generation, sizeof(*generation),
	    workspace, sizeof(*workspace)) ||
	    vmx_nested_state_ranges_overlap(generation, sizeof(*generation),
	    capabilities, sizeof(*capabilities)))
		return (EINVAL);
	error = vmx_nested_msr_workspace_validate(workspace);
	if (error != 0)
		return (error);
	if (workspace->active)
		return (EINVAL);
	error = vmx_nested_capabilities_signature(capabilities, &signature);
	if (error != 0)
		return (error);
	if (signature != workspace->capability_signature)
		return (ESTALE);
	error = vmx_nested_msr_workspace_capacity(capabilities, &required);
	if (error != 0)
		return (error);
	if (workspace->capacity != required)
		return (EPROTO);
	bytes = (size_t)workspace->capacity * sizeof(*workspace->plan);
	if (vmx_nested_state_ranges_overlap(generation, sizeof(*generation),
	    workspace->plan, bytes) ||
	    vmx_nested_state_ranges_overlap(generation, sizeof(*generation),
	    workspace->rollback, bytes))
		return (EINVAL);
	if (entry_load_count > workspace->capacity ||
	    exit_store_count > workspace->capacity ||
	    exit_load_count > workspace->capacity)
		return (E2BIG);
	if (workspace->generation == UINT64_MAX)
		return (EOVERFLOW);
	candidate = workspace->generation + 1;
	workspace->generation = candidate;
	workspace->active = true;
	*generation = candidate;
	return (0);
}

int
vmx_nested_msr_workspace_end(struct vmx_nested_msr_workspace *workspace,
    uint64_t generation)
{

	if (workspace == NULL ||
	    vmx_nested_msr_workspace_validate(workspace) != 0 ||
	    !workspace->active || generation == 0 ||
	    generation != workspace->generation)
		return (ESTALE);
	workspace->active = false;
	return (0);
}

int
vmx_nested_msr_workspace_unbind(struct vmx_nested_msr_workspace *workspace)
{

	if (workspace == NULL)
		return (EINVAL);
	if (workspace->active)
		return (EBUSY);
	vmx_nested_msr_workspace_init(workspace);
	return (0);
}

int
vmx_nested_msr_workspace_validate(
    const struct vmx_nested_msr_workspace *workspace)
{

	if (workspace == NULL)
		return (EINVAL);
	if (workspace->plan == NULL || workspace->rollback == NULL)
		return (workspace->plan == NULL && workspace->rollback == NULL &&
		    workspace->capability_signature == 0 &&
		    workspace->generation == 0 && workspace->capacity == 0 &&
		    !workspace->active ? 0 : EPROTO);
	if (workspace->capability_signature == 0 ||
	    workspace->capacity < 512 || workspace->capacity > 4096 ||
	    (workspace->capacity % 512) != 0 ||
	    nvmx_msr_workspace_overlap(workspace->plan, workspace->rollback,
	    workspace->capacity) ||
	    (workspace->active && workspace->generation == 0))
		return (EPROTO);
	return (0);
}
