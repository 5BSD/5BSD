/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_LATE_ENTRY_H_
#define	_VMM_INTEL_VMX_NESTED_LATE_ENTRY_H_

#include "vmx_nested_types.h"

#include "vmx_nested_attempt.h"
#include "vmx_nested_l2_portable.h"

/*
 * Immutable failed-entry result produced while resuming an already active
 * nested guest.  The retained portable image is the rollback owner until
 * VMCS02 resources are detached.  Bind the architectural failure to that
 * exact image before crossing from the pinned run loop to the frozen owner.
 */
struct vmx_nested_late_entry {
	struct vmx_nested_vmcs02_id	id;
	uint64_t			portable_generation;
	struct vmx_nested_exit_information	exit;
	struct vmx_nested_vmentry_result	result;
};

static __inline bool
vmx_nested_late_entry_equal(const struct vmx_nested_late_entry *a,
    const struct vmx_nested_late_entry *b)
{

	return (a != NULL && b != NULL &&
	    vmx_nested_vmcs02_id_equal(&a->id, &b->id) &&
	    a->portable_generation == b->portable_generation &&
	    vmx_nested_exit_information_equal(&a->exit, &b->exit) &&
	    vmx_nested_vmentry_result_equal(&a->result, &b->result));
}

struct vmx_nested_context;
struct vmx_nested_entry_runtime;
struct vmx_nested_vmentry_handoff_request;

struct vmx_nested_late_entry_commit_ops {
	int	(*commit)(void *, const struct vmx_nested_vmcs02_id *,
		    const struct vmx_nested_vmentry_result *);
};

struct vmx_nested_late_entry_abort_ops {
	int	(*publish)(void *, const struct vmx_nested_vmcs02_id *,
		    uint32_t);
};

int	vmx_nested_late_entry_prepare(
	    const struct vmx_nested_vmcs02_plan *,
	    const struct vmx_nested_l2_portable_state *,
	    const struct vmx_nested_attempt_plan *,
	    struct vmx_nested_late_entry *);
int	vmx_nested_late_entry_validate(
	    const struct vmx_nested_late_entry *,
	    const struct vmx_nested_vmcs02_plan *,
	    const struct vmx_nested_l2_portable_state *);
int	vmx_nested_late_entry_validate_request(
	    const struct vmx_nested_late_entry *);
int	vmx_nested_late_entry_publish(
	    struct vmx_nested_context *,
	    struct vmx_nested_entry_runtime *,
	    const struct vmx_nested_late_entry *);
int	vmx_nested_late_entry_commit(
	    struct vmx_nested_context *,
	    struct vmx_nested_entry_runtime *, bool,
	    const struct vmx_nested_late_entry_commit_ops *, void *,
	    struct vmx_nested_vmentry_handoff_request *);
int	vmx_nested_late_entry_abort(
	    struct vmx_nested_context *,
	    struct vmx_nested_entry_runtime *, bool, uint32_t,
	    const struct vmx_nested_late_entry_abort_ops *, void *,
	    struct vmx_nested_vmentry_handoff_request *);

#endif /* _VMM_INTEL_VMX_NESTED_LATE_ENTRY_H_ */
