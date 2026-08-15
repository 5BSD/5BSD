/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/systm.h>

#include "vmx_nested_state_range.h"
#include "vmx_nested_vpid_owner.h"

void
vmx_nested_vpid_owner_init(struct vmx_nested_vpid_owner *owner)
{

	if (owner != NULL)
		memset(owner, 0, sizeof(*owner));
}

int
vmx_nested_vpid_owner_validate(const struct vmx_nested_vpid_owner *owner)
{
	bool residency_empty;

	if (owner == NULL)
		return (EINVAL);
	if (owner->callback_active)
		return (EBUSY);
	residency_empty = true;
	for (size_t i = 0; i < nitems(owner->resident_cpus); i++)
		residency_empty &= owner->resident_cpus[i] == 0;
	if (!owner->active)
		return (owner->vmcs01_vpid == 0 &&
		    owner->effective_vpid == 0 &&
		    residency_empty ? 0 : EPROTO);
	if (owner->vmcs01_vpid == 0 || owner->effective_vpid == 0 ||
	    owner->vmcs01_vpid == owner->effective_vpid ||
	    (owner->pending_flush && !residency_empty))
		return (EPROTO);
	return (0);
}

int
vmx_nested_vpid_restore_destination_validate(
    const struct vmx_nested_vpid_owner *owner)
{
	int error;

	error = vmx_nested_vpid_owner_validate(owner);
	if (error != 0)
		return (error);
	/*
	 * Restore replaces architectural state, but a VPID and even a pending
	 * pre-allocation invalidation are destination-local ownership.  Neither
	 * may survive publication of an incoming active or inactive vCPU image.
	 */
	if (owner->active || owner->pending_flush)
		return (EBUSY);
	return (0);
}

int
vmx_nested_vpid_owner_acquire(struct vmx_nested_vpid_owner *owner,
    uint16_t vmcs01_vpid, const struct vmx_nested_vpid_owner_ops *ops,
    void *arg)
{
	struct vmx_nested_vpid_owner candidate;
	struct vmx_nested_vpid_owner_ops ops_snapshot;
	uint16_t effective_vpid;
	int error;

	if (owner == NULL || ops == NULL || vmcs01_vpid == 0)
		return (EINVAL);
	if (owner->callback_active)
		return (EBUSY);
	if (vmx_nested_state_ranges_overlap(owner, sizeof(*owner), ops,
	    sizeof(*ops)) || ops->allocate == NULL || ops->release == NULL)
		return (EINVAL);
	error = vmx_nested_vpid_owner_validate(owner);
	if (error != 0)
		return (error);
	if (owner->active)
		return (owner->vmcs01_vpid == vmcs01_vpid ? 0 : ESTALE);
	ops_snapshot = *ops;
	ops = &ops_snapshot;

	effective_vpid = 0;
	owner->callback_active = true;
	error = ops->allocate(arg, &effective_vpid);
	if (error != 0) {
		owner->callback_active = false;
		return (error < 0 ? EPROTO : error);
	}
	if (effective_vpid == 0 || effective_vpid == vmcs01_vpid) {
		if (effective_vpid != 0)
			ops->release(arg, effective_vpid);
		owner->callback_active = false;
		return (ENOSPC);
	}

	memset(&candidate, 0, sizeof(candidate));
	candidate.vmcs01_vpid = vmcs01_vpid;
	candidate.effective_vpid = effective_vpid;
	candidate.active = true;
	/*
	 * The allocator can reuse a destination-local VPID whose translations
	 * still reside on any CPU.  The first final-CPU entry must invalidate
	 * it before use, even when L1 has not issued INVVPID.
	 */
	candidate.pending_flush = true;
	if (vmx_nested_vpid_owner_validate(&candidate) != 0) {
		ops->release(arg, effective_vpid);
		owner->callback_active = false;
		return (EPROTO);
	}
	owner->callback_active = false;
	*owner = candidate;
	return (0);
}

int
vmx_nested_vpid_owner_request_flush(struct vmx_nested_vpid_owner *owner)
{
	int error;

	error = vmx_nested_vpid_owner_validate(owner);
	if (error != 0)
		return (error);
	/*
	 * A frozen L1 may execute INVVPID before its first L2 entry.  Retain
	 * the obligation without allocating a host VPID or executing a
	 * CPU-local invalidation on the frozen-instruction thread.
	 */
	memset(owner->resident_cpus, 0, sizeof(owner->resident_cpus));
	owner->pending_flush = true;
	return (0);
}

bool
vmx_nested_vpid_owner_flush_required(
    const struct vmx_nested_vpid_owner *owner)
{

	return (vmx_nested_vpid_owner_validate(owner) == 0 &&
	    owner->pending_flush);
}

int
vmx_nested_vpid_owner_flush_required_on_cpu(
    const struct vmx_nested_vpid_owner *owner, uint32_t cpu, bool *required)
{
	uint64_t mask;
	int error;

	if (required == NULL || cpu >= VMX_NESTED_VPID_CPU_LIMIT)
		return (EINVAL);
	error = vmx_nested_vpid_owner_validate(owner);
	if (error != 0)
		return (error);
	if (!owner->active)
		return (EINVAL);
	mask = UINT64_C(1) << (cpu % 64U);
	*required = owner->pending_flush ||
	    (owner->resident_cpus[cpu / 64U] & mask) == 0;
	return (0);
}

int
vmx_nested_vpid_owner_flush_complete_on_cpu(
    struct vmx_nested_vpid_owner *owner, uint32_t cpu)
{
	uint64_t mask;
	int error;

	if (cpu >= VMX_NESTED_VPID_CPU_LIMIT)
		return (EINVAL);
	error = vmx_nested_vpid_owner_validate(owner);
	if (error != 0)
		return (error);
	if (!owner->active)
		return (EINVAL);
	mask = UINT64_C(1) << (cpu % 64U);
	owner->resident_cpus[cpu / 64U] |= mask;
	owner->pending_flush = false;
	return (0);
}

int
vmx_nested_vpid_owner_flush_complete(struct vmx_nested_vpid_owner *owner)
{

	/*
	 * Compatibility helper for value-only callers that do not model CPU
	 * migration.  Production must name the pinned logical processor.
	 */
	return (vmx_nested_vpid_owner_flush_complete_on_cpu(owner, 0));
}

int
vmx_nested_vpid_owner_release(struct vmx_nested_vpid_owner *owner,
    const struct vmx_nested_vpid_owner_ops *ops, void *arg)
{
	uint16_t effective_vpid;
	int error;

	if (owner == NULL || ops == NULL)
		return (EINVAL);
	if (owner->callback_active)
		return (EBUSY);
	if (vmx_nested_state_ranges_overlap(owner, sizeof(*owner), ops,
	    sizeof(*ops)) || ops->release == NULL)
		return (EINVAL);
	error = vmx_nested_vpid_owner_validate(owner);
	if (error != 0)
		return (error);
	if (!owner->active) {
		/*
		 * A pre-allocation INVVPID obligation is runtime ownership too.
		 * Releasing the owner cancels that obligation even when no host
		 * identifier has been allocated yet.
		 */
		vmx_nested_vpid_owner_init(owner);
		return (0);
	}

	effective_vpid = owner->effective_vpid;
	owner->callback_active = true;
	ops->release(arg, effective_vpid);
	vmx_nested_vpid_owner_init(owner);
	return (0);
}
