/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#else
#include <sys/systm.h>
#endif

#include "vmx_nested_caps.h"
#include "vmx_nested_compose.h"
#include "vmx_nested_state_range.h"

#define	NVMX_POLICY_PIN_L1_OWNED		\
	((UINT32_C(1) << 6) | (UINT32_C(1) << 7))
#define	NVMX_POLICY_PRIMARY_L1_OWNED	(UINT32_C(1) << 21)
#define	NVMX_POLICY_SECONDARY_L1_OWNED	\
	((UINT32_C(1) << 0) |	/* APIC-access virtualization */	\
	 (UINT32_C(1) << 3) |	/* RDTSCP */				\
	 (UINT32_C(1) << 4) |	/* x2APIC virtualization */		\
	 (UINT32_C(1) << 7) |	/* unrestricted guest */		\
	 (UINT32_C(1) << 8) |	/* APIC-register virtualization */	\
	 (UINT32_C(1) << 9) |	/* virtual-interrupt delivery */	\
	 (UINT32_C(1) << 12) |	/* INVPCID */				\
	 (UINT32_C(1) << 22) |	/* mode-based EPT execute */		\
	 (UINT32_C(1) << 26))	/* user-wait/pause */

bool
vmx_nested_control_policy_valid(
    const struct vmx_nested_control_policy *policy)
{
	uint32_t all;

	if (policy == NULL)
		return (false);
	all = policy->l0_owned | policy->l1_owned | policy->merged |
	    policy->emulated;
	return (all == UINT32_MAX &&
	    (policy->l0_owned & policy->l1_owned) == 0 &&
	    (policy->l0_owned & policy->merged) == 0 &&
	    (policy->l0_owned & policy->emulated) == 0 &&
	    (policy->l1_owned & policy->merged) == 0 &&
	    (policy->l1_owned & policy->emulated) == 0 &&
	    (policy->merged & policy->emulated) == 0);
}

int
vmx_nested_control_policy_validate(
    const struct vmx_nested_control_policy *policy, uint64_t virtual,
    uint64_t hardware)
{
	uint32_t forwarded, hardware_allowed, hardware_required;
	uint32_t virtual_allowed, virtual_required;

	if (!vmx_nested_control_policy_valid(policy))
		return (EINVAL);
	virtual_required = (uint32_t)virtual;
	virtual_allowed = (uint32_t)(virtual >> 32);
	hardware_required = (uint32_t)hardware;
	hardware_allowed = (uint32_t)(hardware >> 32);
	if ((virtual_required & ~virtual_allowed) != 0 ||
	    (hardware_required & ~hardware_allowed) != 0)
		return (EINVAL);

	/*
	 * A control exposed to L1 must either reach hardware or have an
	 * explicit software implementation.  Silently assigning such a bit
	 * to L0 would accept a VMCS12 value whose architectural effect is
	 * discarded.  Forwarded controls must also exist in VMCS02.
	 */
	if ((virtual_allowed & policy->l0_owned) != 0)
		return (ENOTSUP);
	forwarded = policy->l1_owned | policy->merged;
	if ((virtual_allowed & forwarded & ~hardware_allowed) != 0)
		return (ENOTSUP);
	if ((hardware_required & policy->l1_owned & ~virtual_required) != 0)
		return (ENOTSUP);
	return (0);
}

int
vmx_nested_vmcs02_policy_validate(
    const struct vmx_nested_vmcs02_policy *policy,
    const struct vmx_nested_vmcs02_capabilities *virtual,
    const struct vmx_nested_vmcs02_capabilities *hardware)
{
	int error;

	if (policy == NULL || virtual == NULL || hardware == NULL)
		return (EINVAL);
#define	NVMX_VALIDATE_POLICY(member) do {				\
	error = vmx_nested_control_policy_validate(&policy->member,	\
	    virtual->member, hardware->member);				\
	if (error != 0)						\
		return (error);						\
} while (0)
	NVMX_VALIDATE_POLICY(pinbased);
	NVMX_VALIDATE_POLICY(primary);
	NVMX_VALIDATE_POLICY(secondary);
	NVMX_VALIDATE_POLICY(vmexit);
	NVMX_VALIDATE_POLICY(vmentry);
#undef NVMX_VALIDATE_POLICY
	return (0);
}

static struct vmx_nested_control_policy
nvmx_policy_word(uint64_t virtual, bool transition)
{
	struct vmx_nested_control_policy policy;
	uint32_t allowed;

	allowed = (uint32_t)(virtual >> 32);
	memset(&policy, 0, sizeof(policy));
	policy.l0_owned = ~allowed;
	if (transition)
		policy.emulated = allowed;
	else
		policy.merged = allowed;
	return (policy);
}

static void
nvmx_policy_assign_l1(struct vmx_nested_control_policy *policy,
    uint64_t virtual, uint32_t mask)
{
	uint32_t selected;

	selected = (uint32_t)(virtual >> 32) & mask;
	policy->merged &= ~selected;
	policy->l1_owned |= selected;
}

int
vmx_nested_vmcs02_policy_build(
    const struct vmx_nested_vmcs02_capabilities *virtual,
    const struct vmx_nested_vmcs02_capabilities *hardware,
    struct vmx_nested_vmcs02_policy *policy)
{
	struct vmx_nested_vmcs02_policy candidate;
	int error;

	if (virtual == NULL || hardware == NULL || policy == NULL ||
	    vmx_nested_state_ranges_overlap(policy, sizeof(*policy), virtual,
	    sizeof(*virtual)) ||
	    vmx_nested_state_ranges_overlap(policy, sizeof(*policy), hardware,
	    sizeof(*hardware)))
		return (EINVAL);
	memset(&candidate, 0, sizeof(candidate));
	candidate.pinbased = nvmx_policy_word(virtual->pinbased, false);
	candidate.primary = nvmx_policy_word(virtual->primary, false);
	candidate.secondary = nvmx_policy_word(virtual->secondary, false);
	candidate.vmexit = nvmx_policy_word(virtual->vmexit, true);
	candidate.vmentry = nvmx_policy_word(virtual->vmentry, true);
	/*
	 * Intercept controls generally compose as L0 OR L1.  Controls that
	 * enable guest-visible instruction semantics or consume a singleton
	 * VMCS resource do not: VMCS02 must take those from L1, while L0
	 * services its own needs through the nested runtime.  This mirrors
	 * the ownership split used by mature nested-VMX implementations and
	 * prevents an L0 optimization from leaking a feature into L2.
	 */
	nvmx_policy_assign_l1(&candidate.pinbased, virtual->pinbased,
	    NVMX_POLICY_PIN_L1_OWNED);
	nvmx_policy_assign_l1(&candidate.primary, virtual->primary,
	    NVMX_POLICY_PRIMARY_L1_OWNED);
	nvmx_policy_assign_l1(&candidate.secondary, virtual->secondary,
	    NVMX_POLICY_SECONDARY_L1_OWNED);
	error = vmx_nested_vmcs02_policy_validate(&candidate, virtual,
	    hardware);
	if (error != 0)
		return (error);
	*policy = candidate;
	return (0);
}

int
vmx_nested_control_compose(uint32_t l0, uint32_t l1,
    const struct vmx_nested_control_policy *policy, uint64_t hardware,
    uint32_t *result)
{
	uint32_t candidate;

	if (!vmx_nested_control_policy_valid(policy) || result == NULL ||
	    vmx_nested_state_ranges_overlap(result, sizeof(*result), policy,
	    sizeof(*policy)))
		return (EINVAL);
	candidate = (l0 & (policy->l0_owned | policy->emulated)) |
	    (l1 & policy->l1_owned) |
	    ((l0 | l1) & policy->merged);
	if (!vmx_nested_control_valid(candidate, hardware))
		return (ENOTSUP);
	*result = candidate;
	return (0);
}

int
vmx_nested_vmcs02_controls_compose(
    const struct vmx_nested_vmcs02_controls *l0,
    const struct vmx_nested_vmcs02_controls *l1,
    const struct vmx_nested_vmcs02_policy *policy,
    const struct vmx_nested_vmcs02_capabilities *hardware,
    struct vmx_nested_vmcs02_controls *result)
{
	struct vmx_nested_vmcs02_controls candidate;
	int error;

	if (l0 == NULL || l1 == NULL || policy == NULL || hardware == NULL ||
	    result == NULL ||
	    vmx_nested_state_ranges_overlap(result, sizeof(*result), l0,
	    sizeof(*l0)) ||
	    vmx_nested_state_ranges_overlap(result, sizeof(*result), l1,
	    sizeof(*l1)) ||
	    vmx_nested_state_ranges_overlap(result, sizeof(*result), policy,
	    sizeof(*policy)) ||
	    vmx_nested_state_ranges_overlap(result, sizeof(*result), hardware,
	    sizeof(*hardware)))
		return (EINVAL);
	memset(&candidate, 0, sizeof(candidate));
#define	NVMX_COMPOSE_CONTROL(member) do {				\
	error = vmx_nested_control_compose(l0->member, l1->member,	\
	    &policy->member, hardware->member, &candidate.member);	\
	if (error != 0)						\
		return (error);						\
} while (0)
	NVMX_COMPOSE_CONTROL(pinbased);
	NVMX_COMPOSE_CONTROL(primary);
	NVMX_COMPOSE_CONTROL(secondary);
	NVMX_COMPOSE_CONTROL(vmexit);
	NVMX_COMPOSE_CONTROL(vmentry);
#undef NVMX_COMPOSE_CONTROL
	*result = candidate;
	return (0);
}
