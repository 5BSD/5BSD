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

#include "vmx_nested_mtf_owner.h"
#include "vmx_nested_state_range.h"

#define	NVMX_MTF_EXIT_REASON	UINT32_C(37)
#define	NVMX_MTF_PRIMARY_CONTROL	(UINT32_C(1) << 27)

static bool
nvmx_mtf_plan_matches_portable(const struct vmx_nested_vmcs02_plan *plan,
    const struct vmx_nested_l2_portable_state *portable)
{

	return (plan != NULL && portable != NULL &&
	    plan->vmentry.disposition == VMX_NESTED_VMENTRY_READY &&
	    vmx_nested_vmcs02_id_valid(&plan->id) &&
	    vmx_nested_vmcs02_id_equal(&plan->id, &plan->image.id) &&
	    vmx_nested_vmcs02_id_equal(&plan->id, &portable->id) &&
	    (plan->image.controls.primary & NVMX_MTF_PRIMARY_CONTROL) != 0);
}

void
vmx_nested_mtf_owner_init(struct vmx_nested_mtf_owner *owner)
{

	if (owner != NULL)
		memset(owner, 0, sizeof(*owner));
}

int
vmx_nested_mtf_owner_validate(const struct vmx_nested_mtf_owner *owner)
{

	if (owner == NULL)
		return (EINVAL);
	if (owner->callback_active)
		return (EBUSY);
	if (!owner->pending)
		return (owner->origin_generation == 0 &&
		    owner->id.state_generation == 0 &&
		    owner->id.execution_epoch == 0 &&
		    owner->id.vmcs12_gpa == 0 ? 0 : EPROTO);
	if (owner->origin_generation == 0 ||
	    !vmx_nested_vmcs02_id_valid(&owner->id))
		return (EPROTO);
	return (0);
}

int
vmx_nested_mtf_owner_take_portable(struct vmx_nested_mtf_owner *owner,
    struct vmx_nested_l2_portable_state *portable,
    const struct vmx_nested_vmcs02_plan *plan, uint64_t generation)
{
	struct vmx_nested_l2_portable_state portable_candidate;
	struct vmx_nested_mtf_owner owner_candidate;
	int error;

	if (owner == NULL || portable == NULL || plan == NULL || generation == 0 ||
	    vmx_nested_state_ranges_overlap(owner, sizeof(*owner), portable,
	    sizeof(*portable)) ||
	    vmx_nested_state_ranges_overlap(owner, sizeof(*owner), plan,
	    sizeof(*plan)) ||
	    vmx_nested_state_ranges_overlap(portable, sizeof(*portable), plan,
	    sizeof(*plan)))
		return (EINVAL);
	error = vmx_nested_mtf_owner_validate(owner);
	if (error != 0)
		return (error);
	error = vmx_nested_l2_portable_validate(portable);
	if (error != 0)
		return (error);
	if (!nvmx_mtf_plan_matches_portable(plan, portable))
		return (ESTALE);
	if (owner->pending)
		return (EBUSY);
	if (portable->portable_generation != generation)
		return (ESTALE);
	if (!portable->mtf_pending)
		return (ENOENT);

	owner_candidate = *owner;
	owner_candidate.id = portable->id;
	owner_candidate.origin_generation = generation;
	owner_candidate.pending = true;
	portable_candidate = *portable;
	portable_candidate.mtf_pending = false;
	if (vmx_nested_mtf_owner_validate(&owner_candidate) != 0 ||
	    vmx_nested_l2_portable_validate(&portable_candidate) != 0)
		return (EPROTO);
	/* All fallible work is complete before either owner is published. */
	*owner = owner_candidate;
	*portable = portable_candidate;
	return (0);
}

int
vmx_nested_mtf_owner_put_portable(struct vmx_nested_mtf_owner *owner,
    struct vmx_nested_l2_portable_state *portable,
    const struct vmx_nested_vmcs02_plan *plan)
{
	struct vmx_nested_l2_portable_state portable_candidate;
	struct vmx_nested_mtf_owner owner_candidate;
	int error;

	if (owner == NULL || portable == NULL || plan == NULL ||
	    vmx_nested_state_ranges_overlap(owner, sizeof(*owner), portable,
	    sizeof(*portable)) ||
	    vmx_nested_state_ranges_overlap(owner, sizeof(*owner), plan,
	    sizeof(*plan)) ||
	    vmx_nested_state_ranges_overlap(portable, sizeof(*portable), plan,
	    sizeof(*plan)))
		return (EINVAL);
	error = vmx_nested_mtf_owner_validate(owner);
	if (error != 0)
		return (error);
	error = vmx_nested_l2_portable_validate(portable);
	if (error != 0)
		return (error);
	if (!nvmx_mtf_plan_matches_portable(plan, portable))
		return (ESTALE);
	if (!owner->pending)
		return (ENOENT);
	if (!vmx_nested_vmcs02_id_equal(&owner->id, &portable->id))
		return (ESTALE);
	if (portable->portable_generation <= owner->origin_generation)
		return (ESTALE);
	if (portable->mtf_pending)
		return (EBUSY);

	portable_candidate = *portable;
	portable_candidate.mtf_pending = true;
	owner_candidate = *owner;
	vmx_nested_mtf_owner_init(&owner_candidate);
	if (vmx_nested_l2_portable_validate(&portable_candidate) != 0 ||
	    vmx_nested_mtf_owner_validate(&owner_candidate) != 0)
		return (EPROTO);
	/* The captured cold image becomes authoritative at this commit point. */
	*portable = portable_candidate;
	*owner = owner_candidate;
	return (0);
}

int
vmx_nested_mtf_owner_peek(const struct vmx_nested_mtf_owner *owner,
    const struct vmx_nested_vmcs02_id *id, uint64_t origin_generation,
    struct vmx_nested_exit_information *information)
{
	struct vmx_nested_exit_information candidate;
	int error;

	if (information == NULL || id == NULL ||
	    vmx_nested_state_ranges_overlap(information,
	    sizeof(*information), owner, owner == NULL ? 0 : sizeof(*owner)) ||
	    vmx_nested_state_ranges_overlap(information,
	    sizeof(*information), id, sizeof(*id)) ||
	    !vmx_nested_vmcs02_id_valid(id))
		return (EINVAL);
	error = vmx_nested_mtf_owner_validate(owner);
	if (error != 0)
		return (error);
	if (!owner->pending)
		return (ENOENT);
	if (origin_generation == 0 ||
	    origin_generation != owner->origin_generation ||
	    !vmx_nested_vmcs02_id_equal(&owner->id, id))
		return (ESTALE);

	memset(&candidate, 0, sizeof(candidate));
	candidate.exit_reason = NVMX_MTF_EXIT_REASON;
	candidate.launched = true;
	*information = candidate;
	return (0);
}

int
vmx_nested_mtf_owner_consume(struct vmx_nested_mtf_owner *owner,
    const struct vmx_nested_vmcs02_id *id, uint64_t origin_generation)
{
	int error;

	if (id == NULL ||
	    vmx_nested_state_ranges_overlap(owner,
	    owner == NULL ? 0 : sizeof(*owner), id, sizeof(*id)) ||
	    !vmx_nested_vmcs02_id_valid(id))
		return (EINVAL);
	error = vmx_nested_mtf_owner_validate(owner);
	if (error != 0)
		return (error);
	if (!owner->pending)
		return (ENOENT);
	if (origin_generation == 0 ||
	    origin_generation != owner->origin_generation ||
	    !vmx_nested_vmcs02_id_equal(&owner->id, id))
		return (ESTALE);
	vmx_nested_mtf_owner_init(owner);
	return (0);
}

int
vmx_nested_mtf_owner_reflect(struct vmx_nested_mtf_owner *owner,
    const struct vmx_nested_vmcs02_id *id, uint64_t origin_generation,
    const struct vmx_nested_mtf_owner_ops *ops, void *arg)
{
	struct vmx_nested_exit_information information;
	struct vmx_nested_mtf_owner expected;
	int error;

	if (owner == NULL || id == NULL || ops == NULL)
		return (EINVAL);
	if (owner->callback_active)
		return (EBUSY);
	if (ops->publish == NULL ||
	    vmx_nested_state_ranges_overlap(owner, sizeof(*owner), id,
	    sizeof(*id)) ||
	    vmx_nested_state_ranges_overlap(owner, sizeof(*owner), ops,
	    sizeof(*ops)) ||
	    vmx_nested_state_ranges_overlap(id, sizeof(*id), ops,
	    sizeof(*ops)))
		return (EINVAL);
	error = vmx_nested_mtf_owner_peek(owner, id, origin_generation,
	    &information);
	if (error != 0)
		return (error);

	expected = *owner;
	owner->callback_active = true;
	error = ops->publish(arg, id, &information);
	/*
	 * The callback result is the sole publication commit signal.  Restore
	 * the exact pre-callback value before interpreting it: failure retains
	 * the obligation and success consumes it.  There is deliberately no
	 * published-but-retryable result that could duplicate an L1 exit.
	 */
	*owner = expected;
	if (error != 0)
		return (error < 0 ? EPROTO : error);
	vmx_nested_mtf_owner_init(owner);
	return (0);
}

int
vmx_nested_mtf_owner_resolve(struct vmx_nested_mtf_owner *owner,
    const struct vmx_nested_vmcs02_id *id, uint64_t origin_generation,
    const struct vmx_nested_mtf_plan *plan,
    const struct vmx_nested_mtf_owner_ops *ops, void *arg)
{
	struct vmx_nested_exit_information information;
	int error;

	if (owner == NULL || id == NULL || plan == NULL ||
	    vmx_nested_state_ranges_overlap(owner, sizeof(*owner), id,
	    sizeof(*id)) ||
	    vmx_nested_state_ranges_overlap(owner, sizeof(*owner), plan,
	    sizeof(*plan)) ||
	    vmx_nested_state_ranges_overlap(id, sizeof(*id), plan,
	    sizeof(*plan)) ||
	    (ops != NULL &&
	    (vmx_nested_state_ranges_overlap(owner, sizeof(*owner), ops,
	    sizeof(*ops)) ||
	    vmx_nested_state_ranges_overlap(id, sizeof(*id), ops,
	    sizeof(*ops)) ||
	    vmx_nested_state_ranges_overlap(plan, sizeof(*plan), ops,
	    sizeof(*ops)))) || vmx_nested_mtf_plan_validate(plan) != 0)
		return (EINVAL);
	switch (plan->action) {
	case VMX_NESTED_MTF_DEFER:
		/* Validate the exact owner without consuming or publishing it. */
		return (vmx_nested_mtf_owner_peek(owner, id,
		    origin_generation, &information));
	case VMX_NESTED_MTF_DISCARD:
		return (vmx_nested_mtf_owner_consume(owner, id,
		    origin_generation));
	case VMX_NESTED_MTF_REFLECT:
		return (vmx_nested_mtf_owner_reflect(owner, id,
		    origin_generation, ops, arg));
	case VMX_NESTED_MTF_NONE:
	default:
		/* No pending owner has no runtime-resolution transaction. */
		error = vmx_nested_mtf_owner_validate(owner);
		return (error != 0 ? error : EINVAL);
	}
}
