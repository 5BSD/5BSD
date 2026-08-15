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

#include "vmx_nested_vmcs02_lease.h"
#include "vmx_nested_state_range.h"

#define	NVMXL_PIN_POSTED_INTERRUPT	(UINT32_C(1) << 7)
#define	NVMXL_PRIMARY_TPR_SHADOW		(UINT32_C(1) << 21)
#define	NVMXL_SECONDARY_APIC_ACCESS	(UINT32_C(1) << 0)

static bool
nvmxl_id_valid(const struct vmx_nested_vmcs02_id *id)
{

	return (vmx_nested_vmcs02_id_valid(id));
}

static bool
nvmxl_id_equal(const struct vmx_nested_vmcs02_id *a,
    const struct vmx_nested_vmcs02_id *b)
{

	return (vmx_nested_vmcs02_id_equal(a, b));
}

static bool
nvmxl_host_address_valid(uint64_t address, uint64_t length,
    uint64_t alignment)
{

	return (address != UINT64_MAX && alignment != 0 &&
	    (alignment & (alignment - 1)) == 0 &&
	    (address & (alignment - 1)) == 0 &&
	    length != 0 && address <= UINT64_MAX - (length - 1));
}

static int
nvmxl_acquire_one(struct vmx_nested_vmcs02_lease_owner *candidate,
    const struct vmx_nested_vmcs02_lease_ops *ops, void *arg,
    enum vmx_nested_vmcs02_lease_kind kind, uint64_t guest_address,
    uint64_t length, uint64_t alignment, uint64_t *host_address)
{
	struct vmx_nested_vmcs02_lease lease;
	int error;

	if (candidate->count >= nitems(candidate->lease))
		return (EOVERFLOW);
	if (!nvmxl_host_address_valid(guest_address, length, alignment))
		return (EINVAL);
	memset(&lease, 0, sizeof(lease));
	error = ops->acquire(arg, kind, guest_address, length, alignment,
	    &lease);
	if (error != 0)
		return (error < 0 ? EPROTO : error);
	if (lease.kind != kind || lease.guest_address != guest_address ||
	    lease.length != length || lease.alignment != alignment ||
	    !nvmxl_host_address_valid(lease.host_address, length, alignment)) {
		ops->release(arg, &lease);
		return (EPROTO);
	}
	candidate->lease[candidate->count++] = lease;
	*host_address = lease.host_address;
	return (0);
}

static void
nvmxl_release_all(struct vmx_nested_vmcs02_lease_owner *owner,
    const struct vmx_nested_vmcs02_lease_ops *ops, void *arg)
{

	while (owner->count != 0) {
		owner->count--;
		ops->release(arg, &owner->lease[owner->count]);
		memset(&owner->lease[owner->count], 0,
		    sizeof(owner->lease[owner->count]));
	}
}

void
vmx_nested_vmcs02_lease_owner_init(
    struct vmx_nested_vmcs02_lease_owner *owner)
{

	if (owner == NULL)
		return;
	memset(owner, 0, sizeof(*owner));
	owner->id.vmcs12_gpa = UINT64_MAX;
	owner->next_generation = 1;
}

int
vmx_nested_vmcs02_lease_owner_validate(
    const struct vmx_nested_vmcs02_lease_owner *owner)
{
	const struct vmx_nested_vmcs02_lease *lease;
	uint32_t i;

	if (owner == NULL || owner->next_generation == 0 ||
	    owner->count > nitems(owner->lease))
		return (EINVAL);
	if (owner->callback_active)
		return (EBUSY);
	if (!owner->active) {
		if (owner->id.state_generation != 0 ||
		    owner->id.execution_epoch != 0 ||
		    owner->id.vmcs12_gpa != UINT64_MAX ||
		    owner->active_generation != 0 || owner->count != 0)
			return (EPROTO);
	} else if (!nvmxl_id_valid(&owner->id) ||
	    owner->active_generation == 0 ||
	    owner->active_generation >= owner->next_generation) {
		return (EPROTO);
	}
	for (i = 0; i < nitems(owner->lease); i++) {
		lease = &owner->lease[i];
		if (i >= owner->count) {
			if (lease->kind != 0 || lease->guest_address != 0 ||
			    lease->host_address != 0 || lease->length != 0 ||
			    lease->alignment != 0 || lease->cookie != 0)
				return (EPROTO);
			continue;
		}
		if (lease->kind < VMX_NESTED_VMCS02_LEASE_VIRTUAL_APIC ||
		    lease->kind > VMX_NESTED_VMCS02_LEASE_POSTED_INTERRUPT ||
		    !nvmxl_host_address_valid(lease->guest_address,
		    lease->length, lease->alignment) ||
		    !nvmxl_host_address_valid(lease->host_address,
		    lease->length, lease->alignment))
			return (EPROTO);
	}
	return (0);
}

int
vmx_nested_vmcs02_lease_acquire(
    struct vmx_nested_vmcs02_lease_owner *owner,
    const struct vmx_nested_vmcs02_id *id,
    const struct vmx_nested_entry_controls *controls,
    const struct vmx_nested_vmcs02_lease_ops *ops, void *arg,
    const struct vmx_nested_vmcs02_resources *fixed,
    struct vmx_nested_vmcs02_resources *resources)
{
	struct vmx_nested_vmcs02_lease_owner candidate, owner_before;
	struct vmx_nested_vmcs02_lease_ops ops_snapshot;
	struct vmx_nested_vmcs02_resources result;
	int error;

	if (owner == NULL || !nvmxl_id_valid(id) || controls == NULL ||
	    ops == NULL || ops->acquire == NULL || ops->release == NULL ||
	    fixed == NULL || resources == NULL)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(owner, sizeof(*owner), id,
	    sizeof(*id)) ||
	    vmx_nested_state_ranges_overlap(owner, sizeof(*owner), controls,
	    sizeof(*controls)) ||
	    vmx_nested_state_ranges_overlap(owner, sizeof(*owner), ops,
	    sizeof(*ops)) ||
	    vmx_nested_state_ranges_overlap(owner, sizeof(*owner), fixed,
	    sizeof(*fixed)) ||
	    vmx_nested_state_ranges_overlap(owner, sizeof(*owner), resources,
	    sizeof(*resources)) ||
	    vmx_nested_state_ranges_overlap(resources, sizeof(*resources), id,
	    sizeof(*id)) ||
	    vmx_nested_state_ranges_overlap(resources, sizeof(*resources),
	    controls, sizeof(*controls)) ||
	    vmx_nested_state_ranges_overlap(resources, sizeof(*resources), ops,
	    sizeof(*ops)) ||
	    vmx_nested_state_ranges_overlap(resources, sizeof(*resources), fixed,
	    sizeof(*fixed)))
		return (EINVAL);
	error = vmx_nested_vmcs02_lease_owner_validate(owner);
	if (error != 0)
		return (error);
	if (owner->active)
		return (EINVAL);
	if (owner->next_generation == UINT64_MAX)
		return (EOVERFLOW);
	owner_before = *owner;
	ops_snapshot = *ops;
	memset(&candidate, 0, sizeof(candidate));
	candidate.id = *id;
	candidate.next_generation = owner->next_generation;
	result = *fixed;
	result.id = *id;
	result.resource_generation = owner->next_generation;
	owner->callback_active = true;

	if ((controls->primary & NVMXL_PRIMARY_TPR_SHADOW) != 0) {
		error = nvmxl_acquire_one(&candidate, &ops_snapshot, arg,
		    VMX_NESTED_VMCS02_LEASE_VIRTUAL_APIC,
		    controls->virtual_apic, 4096, 4096,
		    &result.virtual_apic);
		if (error != 0)
			goto fail;
	}
	if ((controls->secondary & NVMXL_SECONDARY_APIC_ACCESS) != 0) {
		error = nvmxl_acquire_one(&candidate, &ops_snapshot, arg,
		    VMX_NESTED_VMCS02_LEASE_APIC_ACCESS,
		    controls->apic_access, 4096, 4096,
		    &result.apic_access);
		if (error != 0)
			goto fail;
	}
	if ((controls->pinbased & NVMXL_PIN_POSTED_INTERRUPT) != 0) {
		error = nvmxl_acquire_one(&candidate, &ops_snapshot, arg,
		    VMX_NESTED_VMCS02_LEASE_POSTED_INTERRUPT,
		    controls->posted_interrupt_descriptor, 64, 64,
		    &result.posted_interrupt_descriptor);
		if (error != 0)
			goto fail;
	}

	candidate.active = true;
	candidate.active_generation = candidate.next_generation;
	candidate.next_generation++;
	*owner = candidate;
	*resources = result;
	return (0);

fail:
	nvmxl_release_all(&candidate, &ops_snapshot, arg);
	*owner = owner_before;
	return (error);
}

int
vmx_nested_vmcs02_lease_release(
    struct vmx_nested_vmcs02_lease_owner *owner,
    const struct vmx_nested_vmcs02_id *id, uint64_t generation,
    const struct vmx_nested_vmcs02_lease_ops *ops, void *arg)
{
	struct vmx_nested_vmcs02_lease_owner candidate;
	struct vmx_nested_vmcs02_lease_ops ops_snapshot;
	uint64_t next_generation;
	int error;

	if (owner == NULL || !nvmxl_id_valid(id) || generation == 0 ||
	    ops == NULL || ops->release == NULL)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(owner, sizeof(*owner), id,
	    sizeof(*id)) ||
	    vmx_nested_state_ranges_overlap(owner, sizeof(*owner), ops,
	    sizeof(*ops)))
		return (EINVAL);
	error = vmx_nested_vmcs02_lease_owner_validate(owner);
	if (error != 0)
		return (error);
	if (!owner->active || !nvmxl_id_equal(&owner->id, id) ||
	    owner->active_generation != generation)
		return (EINVAL);
	candidate = *owner;
	ops_snapshot = *ops;
	next_generation = owner->next_generation;
	owner->callback_active = true;
	nvmxl_release_all(&candidate, &ops_snapshot, arg);
	memset(owner, 0, sizeof(*owner));
	owner->id.vmcs12_gpa = UINT64_MAX;
	owner->next_generation = next_generation;
	return (0);
}
