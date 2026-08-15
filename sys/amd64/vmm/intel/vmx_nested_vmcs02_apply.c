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

#include "vmx_nested_vmcs02_apply.h"
#include "vmx_nested_state_range.h"

static int
nvmxa_validate(const struct vmx_nested_vmcs02_program *program,
    const struct vmx_nested_vmcs02_program_apply_ops *ops)
{

	if (program == NULL || ops == NULL || ops->begin == NULL ||
	    ops->write == NULL || ops->commit == NULL || ops->abort == NULL ||
	    !vmx_nested_vmcs02_id_valid(&program->id) ||
	    program->resource_generation == 0 || program->count == 0 ||
	    program->count > VMX_NESTED_VMCS02_PROGRAM_MAX_FIELDS)
		return (EINVAL);
	for (uint32_t i = 1; i < program->count; i++) {
		if (program->fields[i - 1].encoding >=
		    program->fields[i].encoding)
			return (EINVAL);
	}
	return (0);
}

int
vmx_nested_vmcs02_program_apply(
    const struct vmx_nested_vmcs02_program *program,
    const struct vmx_nested_vmcs02_program_apply_ops *ops, void *arg,
    struct vmx_nested_vmcs02_apply_result *result)
{
	struct vmx_nested_vmcs02_program_apply_ops ops_snapshot;
	struct vmx_nested_vmcs02_apply_result candidate;
	int error;

	if (result == NULL ||
	    vmx_nested_state_ranges_overlap(result, sizeof(*result), program,
	    program == NULL ? 0 : sizeof(*program)) ||
	    vmx_nested_state_ranges_overlap(result, sizeof(*result), ops,
	    ops == NULL ? 0 : sizeof(*ops)))
		return (EINVAL);
	error = nvmxa_validate(program, ops);
	if (error != 0)
		return (error);
	ops_snapshot = *ops;
	ops = &ops_snapshot;

	memset(&candidate, 0, sizeof(candidate));
	candidate.id = program->id;
	candidate.resource_generation = program->resource_generation;
	error = ops->begin(arg, &program->id,
	    program->resource_generation);
	if (error != 0)
		return (error);
	for (uint32_t i = 0; i < program->count; i++) {
		error = ops->write(arg, program->fields[i].encoding,
		    program->fields[i].value);
		if (error != 0) {
			ops->abort(arg);
			return (error);
		}
		candidate.writes_completed++;
	}
	error = ops->commit(arg);
	if (error != 0) {
		ops->abort(arg);
		return (error);
	}
	candidate.committed = true;
	*result = candidate;
	return (0);
}
