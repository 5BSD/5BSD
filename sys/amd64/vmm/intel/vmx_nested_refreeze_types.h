/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_REFREEZE_TYPES_H_
#define	_VMM_INTEL_VMX_NESTED_REFREEZE_TYPES_H_

#include "vmx_nested_types.h"
#include "vmx_nested_late_entry.h"

enum vmx_nested_refreeze_purpose {
	VMX_NESTED_REFREEZE_RETRY = 0,
	VMX_NESTED_REFREEZE_LATE_ENTRY,
};

/*
 * Immutable cross-boundary identity.  It deliberately contains no kernel
 * pointer or backend handle: the frozen owner must revalidate it against
 * the vCPU-owned staged transaction before releasing anything.
 */
struct vmx_nested_refreeze_request {
	struct vmx_nested_vmcs02_id id;
	uint64_t portable_generation;
	uint64_t resource_generation;
	enum vmx_nested_refreeze_purpose purpose;
	struct vmx_nested_late_entry late_entry;
};

static __inline bool
vmx_nested_refreeze_request_equal(
    const struct vmx_nested_refreeze_request *a,
    const struct vmx_nested_refreeze_request *b)
{

	return (a != NULL && b != NULL &&
	    vmx_nested_vmcs02_id_equal(&a->id, &b->id) &&
	    a->portable_generation == b->portable_generation &&
	    a->resource_generation == b->resource_generation &&
	    a->purpose == b->purpose &&
	    vmx_nested_late_entry_equal(&a->late_entry, &b->late_entry));
}

int	vmx_nested_refreeze_request_value_validate(
	    const struct vmx_nested_refreeze_request *);

#endif /* _VMM_INTEL_VMX_NESTED_REFREEZE_TYPES_H_ */
