/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/errno.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#else
#include <sys/systm.h>
#endif

#include "vmx_nested_context.h"
#include "vmx_nested_l1_restore.h"
#include "vmx_nested_state_range.h"

static bool
nvmx_l1_restore_id_valid(const struct vmx_nested_vmcs02_id *id)
{

	return (vmx_nested_vmcs02_id_valid(id));
}

int
vmx_nested_l1_restore_failed_entry(const struct vmx_nested_vmcs02_id *id,
    const struct vmx_nested_failed_entry_state_plan *plan,
    const struct vmx_nested_vmentry_result *failure,
    const struct vmx_nested_l1_restore_ops *ops, void *arg,
    struct vmx_nested_l1_restore_result *result)
{
	struct vmx_nested_l1_restore_result candidate;
	struct vmx_nested_l1_restore_ops ops_snapshot;
	bool begun;
	int error;

	if (!nvmx_l1_restore_id_valid(id) || plan == NULL ||
	    failure == NULL || ops == NULL || ops->begin == NULL ||
	    ops->apply_l1 == NULL || ops->commit_vmcs12 == NULL ||
	    ops->commit == NULL || ops->abort == NULL || result == NULL ||
	    failure->disposition != VMX_NESTED_VMENTRY_ENTRY_FAILURE)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(result, sizeof(*result), id,
	    sizeof(*id)) ||
	    vmx_nested_state_ranges_overlap(result, sizeof(*result), plan,
	    sizeof(*plan)) ||
	    vmx_nested_state_ranges_overlap(result, sizeof(*result), failure,
	    sizeof(*failure)) ||
	    vmx_nested_state_ranges_overlap(result, sizeof(*result), ops,
	    sizeof(*ops)))
		return (EINVAL);
	error = vmx_nested_vmentry_rejection_validate(failure);
	if (error != 0)
		return (error);
	ops_snapshot = *ops;
	ops = &ops_snapshot;

	memset(&candidate, 0, sizeof(candidate));
	candidate.id = *id;
	begun = false;
	error = ops->begin(arg, id);
	if (error != 0)
		return (error);
	begun = true;
	error = ops->apply_l1(arg, plan);
	if (error != 0)
		goto fail;
	candidate.steps_completed++;
	error = ops->commit_vmcs12(arg, id, failure);
	if (error != 0)
		goto fail;
	candidate.steps_completed++;
	error = ops->commit(arg);
	if (error != 0)
		goto fail;
	begun = false;
	candidate.committed = true;
	*result = candidate;
	return (0);

fail:
	if (begun)
		ops->abort(arg);
	return (error);
}

int
vmx_nested_l1_restore_vmexit(const struct vmx_nested_vmcs02_id *id,
    const struct vmx_nested_vmexit_state_plan *plan,
    const struct vmx_nested_l1_exit_ops *ops, void *arg,
    struct vmx_nested_l1_exit_result *result)
{
	struct vmx_nested_l1_exit_result candidate;
	struct vmx_nested_l1_exit_ops ops_snapshot;
	bool begun;
	int error;

	if (!nvmx_l1_restore_id_valid(id) || plan == NULL || ops == NULL ||
	    ops->begin == NULL || ops->stage_vmcs12 == NULL ||
	    ops->apply_l1 == NULL || ops->publish_vmcs12 == NULL ||
	    ops->finish == NULL || ops->abort == NULL || result == NULL)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(result, sizeof(*result), id,
	    sizeof(*id)) ||
	    vmx_nested_state_ranges_overlap(result, sizeof(*result), plan,
	    sizeof(*plan)) ||
	    vmx_nested_state_ranges_overlap(result, sizeof(*result), ops,
	    sizeof(*ops)))
		return (EINVAL);
	ops_snapshot = *ops;
	ops = &ops_snapshot;
	memset(&candidate, 0, sizeof(candidate));
	candidate.id = *id;
	begun = false;
	error = ops->begin(arg, id);
	if (error != 0)
		return (error);
	begun = true;
	error = ops->stage_vmcs12(arg, id);
	if (error != 0)
		goto fail;
	candidate.steps_completed++;
	error = ops->apply_l1(arg, plan);
	if (error != 0)
		goto fail;
	candidate.steps_completed++;
	error = ops->publish_vmcs12(arg, id);
	if (error != 0)
		goto fail;
	candidate.steps_completed++;
	ops->finish(arg);
	begun = false;
	candidate.committed = true;
	*result = candidate;
	return (0);

fail:
	if (begun)
		ops->abort(arg);
	return (error);
}
