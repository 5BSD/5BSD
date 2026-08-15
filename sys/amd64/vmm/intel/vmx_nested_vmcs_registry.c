/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/errno.h>
#include <sys/queue.h>
#include <sys/types.h>

#ifdef _KERNEL
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/systm.h>

static MALLOC_DEFINE(M_NVMX_VMCS, "nvmx_vmcs",
    "Nested VMX software VMCS registry");
#else
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#endif

#include "vmx_nested_vmcs_registry.h"
#include "vmx_nested_reflect.h"
#include "vmx_nested_state.h"
#include "vmx_nested_state_range.h"
#include "vmx_nested_vmcs12.h"
#include "vmx_nested_vmcs_store.h"
#include "vmx_nested_vmentry.h"
#include "vmx_nested_vmexit.h"

static uint32_t
nvmx_registry_bucket(uint64_t gpa)
{

	return ((gpa >> VMX_NESTED_VMCS_REGION_SHIFT) &
	    (VMX_NESTED_VMCS_REGISTRY_BUCKETS - 1));
}

static size_t
nvmx_registry_region_size(const struct vmx_nested_vmcs_registry *registry)
{

	return (registry->capabilities.vmcs_region_size);
}

static bool
nvmx_registry_shape_valid(const struct vmx_nested_vmcs_registry *registry)
{

	/*
	 * Registry replacement is the VM-wide nested-state publication point.
	 * Do not let an initialized bit alone legitimize corrupted bookkeeping
	 * or a capability set which could not have initialized a registry.
	 * List-link integrity remains protected by registry ownership and the
	 * enclosing nested_vmcs_sx lock; following arbitrary corrupt links here
	 * would make validation itself unsafe.
	 */
	return (registry != NULL && registry->initialized &&
	    registry->limit != 0 &&
	    registry->limit <= VMX_NESTED_VMCS_REGISTRY_LIMIT &&
	    registry->count <= registry->limit &&
	    vmx_nested_capabilities_validate(&registry->capabilities) == 0 &&
	    registry->capabilities.vmcs_region_size <=
	    VMX_NESTED_VMCS_REGION_SIZE);
}

/*
 * Validate the intrusive-list topology before a lifecycle operation follows
 * links which it may remove or exchange.  The normal per-GPA fast path only
 * needs one bucket, but teardown and replacement must never free through a
 * cycle or a misplaced entry after bookkeeping has been damaged.  Returning
 * false deliberately leaves the registry intact: leaking a corrupted
 * kernel-internal registry during a failed teardown is safer than turning it
 * into a use-after-free traversal.
 */
static bool
nvmx_registry_entries_valid(const struct vmx_nested_vmcs_registry *registry)
{
	struct vmx_nested_vmcs_registry_entry *entry;
	uint32_t seen;

	if (!nvmx_registry_shape_valid(registry))
		return (false);
	seen = 0;
	for (uint32_t bucket = 0;
	    bucket < VMX_NESTED_VMCS_REGISTRY_BUCKETS; bucket++) {
		LIST_FOREACH(entry, &registry->entries[bucket], link) {
			if (seen >= registry->limit ||
			    nvmx_registry_bucket(entry->gpa) != bucket)
				return (false);
			seen++;
		}
	}
	return (seen == registry->count);
}

static bool
nvmx_registry_entries_shared(
    const struct vmx_nested_vmcs_registry *first,
    const struct vmx_nested_vmcs_registry *second)
{
	struct vmx_nested_vmcs_registry_entry *entry;
	uint32_t seen;

	seen = 0;
	for (uint32_t bucket = 0;
	    bucket < VMX_NESTED_VMCS_REGISTRY_BUCKETS; bucket++) {
		LIST_FOREACH(entry, &second->entries[bucket], link) {
			if (seen++ == second->limit)
				return (true);
			if (vmx_nested_vmcs_registry_storage_overlaps(first, entry,
			    sizeof(*entry)))
				return (true);
		}
	}
	return (seen != second->count);
}

static struct vmx_nested_vmcs_registry_entry *
nvmx_registry_alloc(bool waitok)
{

#ifdef _KERNEL
	return (malloc(sizeof(struct vmx_nested_vmcs_registry_entry),
	    M_NVMX_VMCS, (waitok ? M_WAITOK : M_NOWAIT) | M_ZERO));
#else
	(void)waitok;
	return (calloc(1, sizeof(struct vmx_nested_vmcs_registry_entry)));
#endif
}

static void
nvmx_registry_free(struct vmx_nested_vmcs_registry_entry *entry)
{

#ifdef _KERNEL
	free(entry, M_NVMX_VMCS);
#else
	free(entry);
#endif
}

static struct vmx_nested_vmcs_registry_entry *
nvmx_registry_find(struct vmx_nested_vmcs_registry *registry, uint64_t gpa,
    bool *valid)
{
	struct vmx_nested_vmcs_registry_entry *entry, *result;
	uint32_t seen;

	if (valid == NULL || !nvmx_registry_shape_valid(registry)) {
		if (valid != NULL)
			*valid = false;
		return (NULL);
	}
	result = NULL;
	seen = 0;
	LIST_FOREACH(entry,
	    &registry->entries[nvmx_registry_bucket(gpa)], link) {
		if (seen >= registry->limit) {
			*valid = false;
			return (NULL);
		}
		seen++;
		/*
		 * A bucket-local GPA lookup may not skip an entry whose own GPA
		 * hashes elsewhere.  In particular, import is a cold mutating path
		 * and must not add a new region beside damaged bookkeeping.
		 */
		if (nvmx_registry_bucket(entry->gpa) !=
		    nvmx_registry_bucket(gpa)) {
			*valid = false;
			return (NULL);
		}
		if (entry->gpa == gpa) {
			/* One GPA names exactly one opaque VMCS region. */
			if (result != NULL) {
				*valid = false;
				return (NULL);
			}
			result = entry;
		}
	}
	*valid = true;
	return (result);
}

static struct vmx_nested_vmcs_registry_entry *
nvmx_registry_owner(struct vmx_nested_vmcs_registry *registry,
    uint32_t owner, bool *valid)
{
	struct vmx_nested_vmcs_registry_entry *entry, *result;
	uint32_t bucket, seen;

	if (valid == NULL || !nvmx_registry_shape_valid(registry)) {
		if (valid != NULL)
			*valid = false;
		return (NULL);
	}
	result = NULL;
	seen = 0;
	for (bucket = 0; bucket < VMX_NESTED_VMCS_REGISTRY_BUCKETS;
	    bucket++) {
		LIST_FOREACH(entry, &registry->entries[bucket], link) {
			if (seen >= registry->limit) {
				*valid = false;
				return (NULL);
			}
			seen++;
			/* A misplaced entry makes every bucket-local lookup ambiguous. */
			if (nvmx_registry_bucket(entry->gpa) != bucket) {
				*valid = false;
				return (NULL);
			}
			if (entry->owner == owner) {
				/* Ownership is unique VMX architectural state. */
				if (result != NULL) {
					*valid = false;
					return (NULL);
				}
				result = entry;
			}
		}
	}
	*valid = seen == registry->count;
	return (*valid ? result : NULL);
}

static int
nvmx_registry_create(struct vmx_nested_vmcs_registry *registry,
	uint64_t gpa, bool waitok,
	struct vmx_nested_vmcs_registry_entry **result)
{
	struct vmx_nested_vmcs_registry_entry *entry;
	int error;

	if (registry->count >= registry->limit)
		return (ENOSPC);
	entry = nvmx_registry_alloc(waitok);
	if (entry == NULL)
		return (ENOMEM);
	entry->gpa = gpa;
	entry->owner = VMX_NESTED_VMCS_NO_OWNER;
	error = vmx_nested_vmcs_region_init(entry->region,
	    nvmx_registry_region_size(registry), &registry->capabilities,
	    false);
	if (error != 0) {
		nvmx_registry_free(entry);
		return (error);
	}
	LIST_INSERT_HEAD(
	    &registry->entries[nvmx_registry_bucket(gpa)], entry, link);
	registry->count++;
	*result = entry;
	return (0);
}

int
vmx_nested_vmcs_registry_init(struct vmx_nested_vmcs_registry *registry,
    const struct vmx_nested_capabilities *capabilities, uint32_t limit)
{
	uint32_t bucket;

	if (registry == NULL ||
	    vmx_nested_capabilities_validate(capabilities) != 0 ||
	    capabilities->vmcs_region_size > VMX_NESTED_VMCS_REGION_SIZE ||
	    limit == 0 || limit > VMX_NESTED_VMCS_REGISTRY_LIMIT)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(registry, sizeof(*registry),
	    capabilities, sizeof(*capabilities)))
		return (EINVAL);
	memset(registry, 0, sizeof(*registry));
	for (bucket = 0; bucket < VMX_NESTED_VMCS_REGISTRY_BUCKETS;
	    bucket++)
		LIST_INIT(&registry->entries[bucket]);
	registry->capabilities = *capabilities;
	registry->limit = limit;
	registry->initialized = true;
	return (0);
}

int
vmx_nested_vmcs_registry_validate(
    const struct vmx_nested_vmcs_registry *registry)
{

	if (registry == NULL || !registry->initialized)
		return (EINVAL);
	return (nvmx_registry_entries_valid(registry) ? 0 : EPROTO);
}

int
vmx_nested_vmcs_registry_destroy(struct vmx_nested_vmcs_registry *registry)
{
	struct vmx_nested_vmcs_registry_entry *entry;
	uint32_t bucket;

	if (!nvmx_registry_entries_valid(registry))
		return (registry != NULL && registry->initialized ? EPROTO : EINVAL);
	for (bucket = 0; bucket < VMX_NESTED_VMCS_REGISTRY_BUCKETS;
	    bucket++) {
		while ((entry = LIST_FIRST(&registry->entries[bucket])) !=
		    NULL) {
			LIST_REMOVE(entry, link);
			memset(entry, 0, sizeof(*entry));
			nvmx_registry_free(entry);
		}
	}
	memset(registry, 0, sizeof(*registry));
	return (0);
}

int
vmx_nested_vmcs_registry_replace(
    struct vmx_nested_vmcs_registry *destination,
    struct vmx_nested_vmcs_registry *replacement)
{
	struct vmx_nested_vmcs_registry_entry *entry;
	uint32_t count;

	if (destination == replacement ||
	    !nvmx_registry_entries_valid(destination) ||
	    !nvmx_registry_entries_valid(replacement) ||
	    destination->limit != replacement->limit ||
	    !vmx_nested_capabilities_equal(&destination->capabilities,
	    &replacement->capabilities) ||
	    nvmx_registry_entries_shared(destination, replacement))
		return (EINVAL);
	for (uint32_t bucket = 0;
	    bucket < VMX_NESTED_VMCS_REGISTRY_BUCKETS; bucket++) {
		entry = LIST_FIRST(&destination->entries[bucket]);
		destination->entries[bucket].lh_first =
		    replacement->entries[bucket].lh_first;
		if (destination->entries[bucket].lh_first != NULL)
			destination->entries[bucket].lh_first->link.le_prev =
			    &destination->entries[bucket].lh_first;
		replacement->entries[bucket].lh_first = entry;
		if (replacement->entries[bucket].lh_first != NULL)
			replacement->entries[bucket].lh_first->link.le_prev =
			    &replacement->entries[bucket].lh_first;
	}
	count = destination->count;
	destination->count = replacement->count;
	replacement->count = count;
	return (0);
}

bool
vmx_nested_vmcs_registry_storage_overlaps(
    const struct vmx_nested_vmcs_registry *registry, const void *buffer,
    size_t length)
{
	struct vmx_nested_vmcs_registry_entry *entry;
	uint32_t seen;

	if (registry == NULL)
		return (false);
	if (vmx_nested_state_ranges_overlap(buffer, length, registry,
	    sizeof(*registry)))
		return (true);
	/*
	 * Registry entries are independent allocations, not trailing storage.
	 * A restore scratch/output range which aliases one can mutate live VMCS
	 * state before the registry publication point.  Bound the walk by the
	 * validated limit and require the observed count to agree with the
	 * bookkeeping so corrupted lists fail closed instead of looping.
	 */
	if (!nvmx_registry_entries_valid(registry))
		return (true);
	seen = 0;
	for (uint32_t bucket = 0;
	    bucket < VMX_NESTED_VMCS_REGISTRY_BUCKETS; bucket++) {
		LIST_FOREACH(entry, &registry->entries[bucket], link) {
			if (seen == registry->limit)
				return (true);
			seen++;
			if (vmx_nested_state_ranges_overlap(buffer, length, entry,
			    sizeof(*entry)))
				return (true);
		}
	}
	return (seen != registry->count);
}

int
vmx_nested_vmcs_registry_select(struct vmx_nested_vmcs_registry *registry,
    uint64_t gpa, uint32_t revision, uint32_t owner)
{
	struct vmx_nested_vmcs_registry_entry *entry, *previous;
	bool valid;
	int error;

	if (registry == NULL || !registry->initialized ||
	    owner == VMX_NESTED_VMCS_NO_OWNER ||
	    !vmx_nested_region_gpa_valid(&registry->capabilities, gpa) ||
	    !vmx_nested_revision_valid(&registry->capabilities, revision,
	    false))
		return (EINVAL);
	entry = nvmx_registry_find(registry, gpa, &valid);
	if (!valid)
		return (EPROTO);
	if (entry != NULL && entry->owner != VMX_NESTED_VMCS_NO_OWNER &&
	    entry->owner != owner)
		return (EBUSY);
	/*
	 * Validate the complete ownership view before adding a new entry.  The
	 * lookup above intentionally examines only the GPA's hash bucket, while
	 * ownership is unique across the registry.  Were the owner walk delayed
	 * until after nvmx_registry_create(), a malformed list in another bucket
	 * could make this call fail after publishing a new allocation.  Apart from
	 * leaking a registry slot, that would violate the all-or-nothing contract
	 * expected by VMCS selection and checkpoint recovery.
	 */
	previous = nvmx_registry_owner(registry, owner, &valid);
	if (!valid)
		return (EPROTO);
	if (entry == NULL) {
		/*
		 * VMCS selection is performed by the frozen VMX-instruction
		 * handoff.  Do not make that serialized vCPU path wait for memory:
		 * the caller preserves ENOMEM as a recoverable host failure and can
		 * retry after the VM_RUN boundary.
		 */
		error = nvmx_registry_create(registry, gpa, false, &entry);
		if (error != 0)
			return (error);
	}
	if (previous != NULL && previous != entry)
		previous->owner = VMX_NESTED_VMCS_NO_OWNER;
	entry->owner = owner;
	return (0);
}

int
vmx_nested_vmcs_registry_owner_active(
    const struct vmx_nested_vmcs_registry *registry, uint32_t owner,
    bool *active)
{
	struct vmx_nested_vmcs_registry_entry *entry;
	uint32_t matches, seen;

	if (registry == NULL || !registry->initialized ||
	    owner == VMX_NESTED_VMCS_NO_OWNER || active == NULL)
		return (EINVAL);
	/* Keep corrupt topology distinct from an output-alias contract error. */
	if (!nvmx_registry_entries_valid(registry))
		return (EPROTO);
	if (vmx_nested_vmcs_registry_storage_overlaps(registry, active,
	    sizeof(*active)))
		return (EINVAL);
	matches = 0;
	seen = 0;
	for (uint32_t bucket = 0;
	    bucket < VMX_NESTED_VMCS_REGISTRY_BUCKETS; bucket++) {
		LIST_FOREACH(entry, &registry->entries[bucket], link) {
			if (seen == registry->limit)
				return (EPROTO);
			seen++;
			if (nvmx_registry_bucket(entry->gpa) != bucket)
				return (EPROTO);
			if (entry->owner == owner && ++matches > 1)
				return (EPROTO);
		}
	}
	if (seen != registry->count)
		return (EPROTO);
	*active = matches != 0;
	return (0);
}

int
vmx_nested_vmcs_registry_release(struct vmx_nested_vmcs_registry *registry,
    uint32_t owner)
{
	struct vmx_nested_vmcs_registry_entry *entry;
	bool valid;

	if (registry == NULL || !registry->initialized ||
	    owner == VMX_NESTED_VMCS_NO_OWNER)
		return (EINVAL);
	entry = nvmx_registry_owner(registry, owner, &valid);
	if (!valid)
		return (EPROTO);
	if (entry == NULL)
		return (ENOENT);
	entry->owner = VMX_NESTED_VMCS_NO_OWNER;
	return (0);
}

int
vmx_nested_vmcs_registry_clear(struct vmx_nested_vmcs_registry *registry,
    uint64_t gpa, uint32_t owner)
{
	struct vmx_nested_vmcs_registry_entry *entry;
	bool valid;
	int error;

	if (registry == NULL || !registry->initialized ||
	    owner == VMX_NESTED_VMCS_NO_OWNER ||
	    !vmx_nested_region_gpa_valid(&registry->capabilities, gpa))
		return (EINVAL);
	entry = nvmx_registry_find(registry, gpa, &valid);
	if (!valid)
		return (EPROTO);
	if (entry == NULL)
		return (ENOENT);
	if (entry->owner != VMX_NESTED_VMCS_NO_OWNER &&
	    entry->owner != owner)
		return (EBUSY);
	error = vmx_nested_vmcs_region_clear(entry->region,
	    nvmx_registry_region_size(registry), &registry->capabilities,
	    false);
	if (error == 0)
		entry->owner = VMX_NESTED_VMCS_NO_OWNER;
	return (error);
}

static int
nvmx_registry_owned(struct vmx_nested_vmcs_registry *registry,
    uint64_t gpa, uint32_t owner,
    struct vmx_nested_vmcs_registry_entry **result)
{
	struct vmx_nested_vmcs_registry_entry *entry;
	bool valid;

	if (registry == NULL || !registry->initialized ||
	    owner == VMX_NESTED_VMCS_NO_OWNER)
		return (EINVAL);
	entry = nvmx_registry_find(registry, gpa, &valid);
	if (!valid)
		return (EPROTO);
	if (entry == NULL || entry->owner != owner)
		return (ESTALE);
	*result = entry;
	return (0);
}

int
vmx_nested_vmcs_registry_read(struct vmx_nested_vmcs_registry *registry,
    uint64_t gpa, uint32_t owner, uint32_t encoding, uint64_t *value)
{
	struct vmx_nested_vmcs_registry_entry *entry;
	int error;

	if (value == NULL)
		return (EINVAL);
	error = nvmx_registry_owned(registry, gpa, owner, &entry);
	if (error != 0)
		return (error);
	if (vmx_nested_vmcs_registry_storage_overlaps(registry, value,
	    sizeof(*value)))
		return (EINVAL);
	return (vmx_nested_vmcs_region_read(entry->region,
	    nvmx_registry_region_size(registry), &registry->capabilities,
	    false, encoding, value));
}

int
vmx_nested_vmcs_registry_snapshot(struct vmx_nested_vmcs_registry *registry,
    uint64_t gpa, uint32_t owner, bool in_smm,
    struct vmx_nested_vmcs12_snapshot *snapshot)
{
	struct vmx_nested_vmcs_registry_entry *entry;
	int error;

	if (snapshot == NULL)
		return (EINVAL);
	error = nvmx_registry_owned(registry, gpa, owner, &entry);
	if (error != 0)
		return (error);
	if (vmx_nested_vmcs_registry_storage_overlaps(registry, snapshot,
	    sizeof(*snapshot)))
		return (EINVAL);
	return (vmx_nested_vmcs12_snapshot_region(entry->region,
	    nvmx_registry_region_size(registry), &registry->capabilities,
	    gpa, in_smm, snapshot));
}

int
vmx_nested_vmcs_registry_set_launched(
    struct vmx_nested_vmcs_registry *registry, uint64_t gpa, uint32_t owner,
    uint64_t epoch)
{
	struct vmx_nested_vmcs_registry_entry *entry;
	int error;

	if (epoch == 0)
		return (EINVAL);
	error = nvmx_registry_owned(registry, gpa, owner, &entry);
	if (error != 0)
		return (error);
	return (vmx_nested_vmcs_region_set_launched(entry->region,
	    nvmx_registry_region_size(registry), &registry->capabilities,
	    false, true, epoch));
}

int
vmx_nested_vmcs_registry_write(struct vmx_nested_vmcs_registry *registry,
    uint64_t gpa, uint32_t owner, uint32_t encoding, uint64_t value)
{
	struct vmx_nested_vmcs_registry_entry *entry;
	int error;

	error = nvmx_registry_owned(registry, gpa, owner, &entry);
	if (error != 0)
		return (error);
	return (vmx_nested_vmcs_region_write(entry->region,
	    nvmx_registry_region_size(registry), &registry->capabilities,
	    false, encoding, value));
}

int
vmx_nested_vmcs_registry_set_instruction_error(
    struct vmx_nested_vmcs_registry *registry, uint64_t gpa, uint32_t owner,
    uint32_t instruction_error)
{
	struct vmx_nested_vmcs_registry_entry *entry;
	int error;

	error = nvmx_registry_owned(registry, gpa, owner, &entry);
	if (error != 0)
		return (error);
	return (vmx_nested_vmcs_region_set_instruction_error(entry->region,
	    nvmx_registry_region_size(registry), &registry->capabilities,
	    false, instruction_error));
}

static int
nvmx_registry_import(
    struct vmx_nested_vmcs_registry *registry, uint64_t gpa,
    const struct vmx_nested_field *fields, uint32_t count, bool launched,
    uint64_t epoch, uint32_t abort_indicator, bool waitok)
{
	struct vmx_nested_vmcs_registry_entry *entry;
	size_t fields_length;
	bool valid;
	int error;

	if (registry == NULL || !registry->initialized ||
	    !vmx_nested_region_gpa_valid(&registry->capabilities, gpa) ||
	    abort_indicator > 6)
		return (EINVAL);
	entry = nvmx_registry_find(registry, gpa, &valid);
	if (!valid)
		return (EPROTO);
	if (entry != NULL)
		return (EINVAL);
	fields_length = (size_t)count * sizeof(*fields);
	if (count != 0 && fields_length / sizeof(*fields) != count)
		return (EOVERFLOW);
	if (count != 0 && vmx_nested_vmcs_registry_storage_overlaps(registry,
	    fields, fields_length))
		return (EINVAL);
	error = nvmx_registry_create(registry, gpa, waitok, &entry);
	if (error != 0)
		return (error);
	error = vmx_nested_vmcs_region_import(entry->region,
	    nvmx_registry_region_size(registry), &registry->capabilities,
	    false, fields, count, launched, epoch);
	if (error == 0 && abort_indicator != 0)
		error = vmx_nested_vmcs_region_set_abort_indicator(
		    entry->region, nvmx_registry_region_size(registry),
		    &registry->capabilities, false, abort_indicator);
	if (error != 0) {
		LIST_REMOVE(entry, link);
		registry->count--;
		memset(entry, 0, sizeof(*entry));
		nvmx_registry_free(entry);
	}
	return (error);
}

int
vmx_nested_vmcs_registry_import(
    struct vmx_nested_vmcs_registry *registry, uint64_t gpa,
    const struct vmx_nested_field *fields, uint32_t count, bool launched,
    uint64_t epoch, uint32_t abort_indicator)
{

	return (nvmx_registry_import(registry, gpa, fields, count, launched,
	    epoch, abort_indicator, true));
}

int
vmx_nested_vmcs_registry_import_nowait(
    struct vmx_nested_vmcs_registry *registry, uint64_t gpa,
    const struct vmx_nested_field *fields, uint32_t count, bool launched,
    uint64_t epoch, uint32_t abort_indicator)
{

	return (nvmx_registry_import(registry, gpa, fields, count, launched,
	    epoch, abort_indicator, false));
}

int
vmx_nested_vmcs_registry_commit_ept_exit(
    struct vmx_nested_vmcs_registry *registry, uint64_t gpa, uint32_t owner,
    const struct vmx_nested_exit_information *hardware, uint64_t epoch)
{
	struct vmx_nested_vmcs_registry_entry *entry, *scratch;
	int error;

	if (hardware == NULL || epoch == 0)
		return (EINVAL);
	error = nvmx_registry_owned(registry, gpa, owner, &entry);
	if (error != 0)
		return (error);
	if (vmx_nested_vmcs_registry_storage_overlaps(registry, hardware,
	    sizeof(*hardware)))
		return (EINVAL);
	scratch = nvmx_registry_alloc(true);
	if (scratch == NULL)
		return (ENOMEM);
	error = vmx_nested_vmcs_region_commit_ept_exit_information(
	    entry->region, nvmx_registry_region_size(registry),
	    &registry->capabilities,
	    false, hardware, epoch, scratch->region,
	    nvmx_registry_region_size(registry));
	memset(scratch, 0, sizeof(*scratch));
	nvmx_registry_free(scratch);
	return (error);
}

int
vmx_nested_vmcs_registry_prepare_vmexit(
    struct vmx_nested_vmcs_registry *registry, uint64_t gpa, uint32_t owner,
    const struct vmx_nested_vmexit_state_input *state_input,
    const struct vmx_nested_exit_information *hardware, uint64_t epoch,
    void *scratch, size_t scratch_length)
{
	struct vmx_nested_vmcs_registry_entry *entry;
	int error;

	if (state_input == NULL || hardware == NULL || epoch == 0 ||
	    scratch == NULL)
		return (EINVAL);
	error = nvmx_registry_owned(registry, gpa, owner, &entry);
	if (error != 0)
		return (error);
	if (vmx_nested_vmcs_registry_storage_overlaps(registry, state_input,
	    sizeof(*state_input)) ||
	    vmx_nested_vmcs_registry_storage_overlaps(registry, hardware,
	    sizeof(*hardware)) ||
	    vmx_nested_vmcs_registry_storage_overlaps(registry, scratch,
	    scratch_length) ||
	    vmx_nested_state_ranges_overlap(scratch, scratch_length,
	    state_input, sizeof(*state_input)) ||
	    vmx_nested_state_ranges_overlap(scratch, scratch_length, hardware,
	    sizeof(*hardware)))
		return (EINVAL);
	return (vmx_nested_vmcs_region_prepare_vmexit(entry->region,
	    nvmx_registry_region_size(registry), &registry->capabilities,
	    false, state_input, hardware, epoch, scratch, scratch_length));
}

int
vmx_nested_vmcs_registry_publish_vmexit(
    struct vmx_nested_vmcs_registry *registry, uint64_t gpa, uint32_t owner,
    const void *prepared, size_t prepared_length, uint64_t epoch)
{
	struct vmx_nested_vmcs_registry_entry *entry;
	uint64_t prepared_epoch;
	uint32_t count;
	bool launched;
	int error;

	if (prepared == NULL || registry == NULL || !registry->initialized ||
	    prepared_length != nvmx_registry_region_size(registry) ||
	    epoch == 0)
		return (EINVAL);
	error = nvmx_registry_owned(registry, gpa, owner, &entry);
	if (error != 0)
		return (error);
	/*
	 * A staging image is external to the registry entry.  Reject any
	 * partial alias before validating or copying it.
	 */
	if (vmx_nested_vmcs_registry_storage_overlaps(registry, prepared,
	    prepared_length))
		return (EINVAL);
	error = vmx_nested_vmcs_region_field_count(prepared, prepared_length,
	    &registry->capabilities, false, &count);
	if (error == 0)
		error = vmx_nested_vmcs_region_launched(prepared,
		    prepared_length, &registry->capabilities, false,
		    &launched, &prepared_epoch);
	if (error != 0)
		return (error);
	if (!launched || prepared_epoch != epoch)
		return (ESTALE);
	memcpy(entry->region, prepared, prepared_length);
	return (0);
}

int
vmx_nested_vmcs_registry_commit_vmexit(
    struct vmx_nested_vmcs_registry *registry, uint64_t gpa, uint32_t owner,
    const struct vmx_nested_vmexit_state_input *state_input,
    const struct vmx_nested_exit_information *hardware, uint64_t epoch,
    void *scratch, size_t scratch_length)
{
	int error;

	error = vmx_nested_vmcs_registry_prepare_vmexit(registry, gpa, owner,
	    state_input, hardware, epoch, scratch, scratch_length);
	if (error != 0)
		return (error);
	return (vmx_nested_vmcs_registry_publish_vmexit(registry, gpa, owner,
	    scratch, scratch_length, epoch));
}

int
vmx_nested_vmcs_registry_commit_vmentry_failure(
    struct vmx_nested_vmcs_registry *registry, uint64_t gpa, uint32_t owner,
    const struct vmx_nested_vmentry_result *result)
{
	struct vmx_nested_vmcs_registry_entry *entry, *scratch;
	int error;

	if (result == NULL)
		return (EINVAL);
	error = nvmx_registry_owned(registry, gpa, owner, &entry);
	if (error != 0)
		return (error);
	if (vmx_nested_vmcs_registry_storage_overlaps(registry, result,
	    sizeof(*result)))
		return (EINVAL);
	scratch = nvmx_registry_alloc(true);
	if (scratch == NULL)
		return (ENOMEM);
	error = vmx_nested_vmcs_region_commit_vmentry_failure(entry->region,
	    nvmx_registry_region_size(registry), &registry->capabilities,
	    false, result, scratch->region,
	    nvmx_registry_region_size(registry));
	memset(scratch, 0, sizeof(*scratch));
	nvmx_registry_free(scratch);
	return (error);
}

int
vmx_nested_vmcs_registry_launched(
    struct vmx_nested_vmcs_registry *registry, uint64_t gpa, uint32_t owner,
    bool *launched, uint64_t *epoch)
{
	struct vmx_nested_vmcs_registry_entry *entry;
	int error;

	if (launched == NULL || epoch == NULL)
		return (EINVAL);
	error = nvmx_registry_owned(registry, gpa, owner, &entry);
	if (error != 0)
		return (error);
	if (vmx_nested_vmcs_registry_storage_overlaps(registry, launched,
	    sizeof(*launched)) ||
	    vmx_nested_vmcs_registry_storage_overlaps(registry, epoch,
	    sizeof(*epoch)) ||
	    vmx_nested_state_ranges_overlap(launched, sizeof(*launched), epoch,
	    sizeof(*epoch)))
		return (EINVAL);
	return (vmx_nested_vmcs_region_launched(entry->region,
	    nvmx_registry_region_size(registry), &registry->capabilities,
	    false, launched, epoch));
}

int
vmx_nested_vmcs_registry_abort_indicator(
    struct vmx_nested_vmcs_registry *registry, uint64_t gpa, uint32_t owner,
    uint32_t *indicator)
{
	struct vmx_nested_vmcs_registry_entry *entry;
	int error;

	if (indicator == NULL)
		return (EINVAL);
	error = nvmx_registry_owned(registry, gpa, owner, &entry);
	if (error != 0)
		return (error);
	if (vmx_nested_vmcs_registry_storage_overlaps(registry, indicator,
	    sizeof(*indicator)))
		return (EINVAL);
	return (vmx_nested_vmcs_region_abort_indicator(entry->region,
	    nvmx_registry_region_size(registry), &registry->capabilities,
	    false, indicator));
}

int
vmx_nested_vmcs_registry_set_abort_indicator(
    struct vmx_nested_vmcs_registry *registry, uint64_t gpa, uint32_t owner,
    uint32_t indicator)
{
	struct vmx_nested_vmcs_registry_entry *entry;
	int error;

	if (indicator == 0 || indicator > 6)
		return (EINVAL);
	error = nvmx_registry_owned(registry, gpa, owner, &entry);
	if (error != 0)
		return (error);
	return (vmx_nested_vmcs_region_set_abort_indicator(entry->region,
	    nvmx_registry_region_size(registry), &registry->capabilities,
	    false, indicator));
}
