/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/endian.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/types.h>

#ifdef _KERNEL
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/systm.h>

static MALLOC_DEFINE(M_NVMX_REGSTATE, "nvmx_regstate",
    "Nested VMX registry checkpoint scratch");
#else
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#endif

#include "vmx_nested_caps.h"
#include "vmx_nested_state.h"
#include "vmx_nested_state_range.h"
#include "vmx_nested_vmcs.h"
#include "vmx_nested_vmcs_registry.h"
#include "vmx_nested_vmcs_registry_state.h"
#include "vmx_nested_vmcs_store.h"

#define	NVMXRS_MAGIC		UINT32_C(0x3152564e)	/* "NVR1" */
#define	NVMXRS_VERSION		2U
#define	NVMXRS_HEADER_SIZE	64U
#define	NVMXRS_CAPABILITIES_SIZE	VMX_NESTED_CAPABILITIES_WIRE_SIZE
#define	NVMXRS_ENTRY_SIZE	32U
#define	NVMXRS_FIELD_SIZE	16U
#define	NVMXRS_DIGEST_OFFSET	40U
#define	NVMXRS_F_LAUNCHED	0x00000001U

static uint64_t
nvmxrs_digest(const uint8_t *bytes, size_t length)
{
	uint64_t digest;

	digest = UINT64_C(14695981039346656037);
	for (size_t i = 0; i < length; i++) {
		uint8_t byte;

		byte = i >= NVMXRS_DIGEST_OFFSET &&
		    i < NVMXRS_DIGEST_OFFSET + sizeof(uint64_t) ?
		    0 : bytes[i];
		digest ^= byte;
		digest *= UINT64_C(1099511628211);
	}
	return (digest);
}

static struct vmx_nested_vmcs_registry_entry *
nvmxrs_next(const struct vmx_nested_vmcs_registry *registry, bool first,
    uint64_t previous, bool *valid)
{
	struct vmx_nested_vmcs_registry_entry *entry, *next;
	uint32_t seen;

	if (valid == NULL || registry == NULL || registry->limit == 0) {
		if (valid != NULL)
			*valid = false;
		return (NULL);
	}
	/*
	 * This walker is used to canonicalize a VMCS registry for checkpoint
	 * encoding.  Registry ownership normally protects list integrity, but a
	 * corrupt next link must not turn a diagnostic or checkpoint request into
	 * an unbounded kernel loop.  The immutable registry limit is also the
	 * maximum number of independently allocated entries, so it is a natural
	 * traversal bound.  Callers distinguish this malformed state from an
	 * ordinary end-of-list and fail the transaction without publication.
	 */
	next = NULL;
	seen = 0;
	for (uint32_t bucket = 0;
	    bucket < VMX_NESTED_VMCS_REGISTRY_BUCKETS; bucket++) {
		LIST_FOREACH(entry, &registry->entries[bucket], link) {
			if (seen >= registry->limit) {
				*valid = false;
				return (NULL);
			}
			seen++;
			if ((!first && entry->gpa <= previous) ||
			    (next != NULL && entry->gpa >= next->gpa))
				continue;
			next = entry;
		}
	}
	*valid = true;
	return (next);
}

static int
nvmxrs_total(const struct vmx_nested_vmcs_registry *registry, size_t *total)
{
	struct vmx_nested_vmcs_registry_entry *entry;
	uint32_t fields, seen;
	size_t candidate;
	uint64_t previous;
	bool first, valid;
	int error;

	if (registry == NULL || total == NULL)
		return (EINVAL);
	error = vmx_nested_vmcs_registry_validate(registry);
	if (error != 0)
		return (error);
	candidate = NVMXRS_HEADER_SIZE + NVMXRS_CAPABILITIES_SIZE;
	previous = 0;
	first = true;
	seen = 0;
	valid = true;
	while ((entry = nvmxrs_next(registry, first, previous, &valid)) !=
	    NULL) {
		error = vmx_nested_vmcs_region_field_count(entry->region,
		    sizeof(entry->region), &registry->capabilities, false,
		    &fields);
		if (error != 0)
			return (error);
		if (fields > VMX_NESTED_STATE_MAX_FIELDS ||
		    candidate > SIZE_MAX - NVMXRS_ENTRY_SIZE -
		    (size_t)fields * NVMXRS_FIELD_SIZE)
			return (EOVERFLOW);
		candidate += NVMXRS_ENTRY_SIZE +
		    (size_t)fields * NVMXRS_FIELD_SIZE;
		previous = entry->gpa;
		first = false;
		seen++;
	}
	if (!valid || seen != registry->count || candidate > UINT32_MAX)
		return (EPROTO);
	*total = candidate;
	return (0);
}

int
vmx_nested_vmcs_registry_state_size(
    const struct vmx_nested_vmcs_registry *registry, size_t *size)
{
	size_t total;
	int error;

	if (size == NULL)
		return (EINVAL);
	error = nvmxrs_total(registry, &total);
	if (error != 0)
		return (error);
	if (vmx_nested_vmcs_registry_storage_overlaps(registry, size,
	    sizeof(*size)))
		return (EINVAL);
	*size = total;
	return (0);
}

int
vmx_nested_vmcs_registry_state_encode(
    const struct vmx_nested_vmcs_registry *registry, void *buffer,
    size_t capacity, size_t *written)
{
	struct vmx_nested_vmcs_registry_entry *entry;
	struct vmx_nested_field field;
	uint8_t *bytes, *cursor;
	uint64_t capability_signature, epoch, previous;
	uint32_t abort_indicator, fields, flags, seen;
	size_t total;
	bool first, launched, valid;
	int error;

	if (buffer == NULL || written == NULL)
		return (EINVAL);
	error = nvmxrs_total(registry, &total);
	if (error != 0)
		return (error);
	if (vmx_nested_state_ranges_overlap(buffer, total, written,
	    sizeof(*written)) ||
	    vmx_nested_vmcs_registry_storage_overlaps(registry, buffer, total) ||
	    vmx_nested_vmcs_registry_storage_overlaps(registry, written,
	    sizeof(*written)))
		return (EINVAL);
	*written = 0;
	if (capacity < total)
		return (ENOSPC);
	error = vmx_nested_capabilities_signature(&registry->capabilities,
	    &capability_signature);
	if (error != 0)
		return (error);

	bytes = buffer;
	memset(bytes, 0, total);
	le32enc(bytes, NVMXRS_MAGIC);
	le16enc(bytes + 4, NVMXRS_VERSION);
	le16enc(bytes + 6, NVMXRS_HEADER_SIZE);
	le32enc(bytes + 8, (uint32_t)total);
	le32enc(bytes + 12, registry->count);
	le32enc(bytes + 16, registry->limit);
	le64enc(bytes + 24, capability_signature);
	le64enc(bytes + 32, vmx_nested_vmcs_schema_signature());
	error = vmx_nested_capabilities_wire_encode(&registry->capabilities,
	    bytes + NVMXRS_HEADER_SIZE, NVMXRS_CAPABILITIES_SIZE);
	if (error != 0)
		return (error);
	cursor = bytes + NVMXRS_HEADER_SIZE + NVMXRS_CAPABILITIES_SIZE;
	previous = 0;
	first = true;
	seen = 0;
	valid = true;
	while ((entry = nvmxrs_next(registry, first, previous, &valid)) !=
	    NULL) {
		error = vmx_nested_vmcs_region_field_count(entry->region,
		    sizeof(entry->region), &registry->capabilities, false,
		    &fields);
		if (error != 0)
			return (error);
		error = vmx_nested_vmcs_region_launched(entry->region,
		    sizeof(entry->region), &registry->capabilities, false,
		    &launched, &epoch);
		if (error != 0)
			return (error);
		error = vmx_nested_vmcs_region_abort_indicator(entry->region,
		    sizeof(entry->region), &registry->capabilities, false,
		    &abort_indicator);
		if (error != 0)
			return (error);
		flags = launched ? NVMXRS_F_LAUNCHED : 0;
		le64enc(cursor, entry->gpa);
		le64enc(cursor + 8, epoch);
		le32enc(cursor + 16, fields);
		le32enc(cursor + 20, abort_indicator);
		le32enc(cursor + 24, flags);
		cursor += NVMXRS_ENTRY_SIZE;
		for (uint32_t i = 0; i < fields; i++) {
			error = vmx_nested_vmcs_region_field(entry->region,
			    sizeof(entry->region), &registry->capabilities,
			    false, i, &field);
			if (error != 0)
				return (error);
			le32enc(cursor, field.encoding);
			cursor[4] = field.width;
			le64enc(cursor + 8, field.value);
			cursor += NVMXRS_FIELD_SIZE;
		}
		previous = entry->gpa;
		first = false;
		seen++;
	}
	if (!valid || seen != registry->count ||
	    cursor != bytes + total)
		return (EPROTO);
	le64enc(bytes + NVMXRS_DIGEST_OFFSET,
	    nvmxrs_digest(bytes, total));
	*written = total;
	return (0);
}

static struct vmx_nested_field *
nvmxrs_fields_alloc(uint32_t count)
{

	if (count == 0)
		return (NULL);
#ifdef _KERNEL
	return (malloc((size_t)count * sizeof(struct vmx_nested_field),
	    M_NVMX_REGSTATE, M_NOWAIT | M_ZERO));
#else
	return (calloc(count, sizeof(struct vmx_nested_field)));
#endif
}

static void
nvmxrs_fields_free(struct vmx_nested_field *fields)
{

	if (fields == NULL)
		return;
#ifdef _KERNEL
	free(fields, M_NVMX_REGSTATE);
#else
	free(fields);
#endif
}

static int
nvmxrs_current_matches(struct vmx_nested_vmcs_registry *registry,
    const struct vmx_nested_state_view *view)
{
	struct vmx_nested_vmcs_registry_entry *entry;
	struct vmx_nested_field actual, expected;
	uint64_t epoch;
	uint32_t abort_indicator, count, seen;
	bool found;
	bool launched;
	int error;

	if (view == NULL ||
	    view->current_vmcs_gpa == VMX_NESTED_STATE_INVALID_GPA)
		return (0);
	error = vmx_nested_vmcs_registry_validate(registry);
	if (error != 0)
		return (error);
	entry = NULL;
	found = false;
	seen = 0;
	for (uint32_t bucket = 0;
	    bucket < VMX_NESTED_VMCS_REGISTRY_BUCKETS; bucket++) {
		struct vmx_nested_vmcs_registry_entry *candidate;

		LIST_FOREACH(candidate, &registry->entries[bucket], link) {
			if (seen >= registry->limit)
				return (EPROTO);
			seen++;
			if (candidate->gpa != view->current_vmcs_gpa)
				continue;
			if (found)
				return (EPROTO);
			entry = candidate;
			found = true;
		}
	}
	if (seen != registry->count || entry == NULL)
		return (EPROTO);
	error = vmx_nested_vmcs_region_field_count(entry->region,
	    sizeof(entry->region), &registry->capabilities, false, &count);
	if (error != 0)
		return (error);
	if (count != view->vmcs_field_count)
		return (EPROTO);
	for (uint32_t i = 0; i < count; i++) {
		error = vmx_nested_vmcs_region_field(entry->region,
		    sizeof(entry->region), &registry->capabilities, false, i,
		    &actual);
		if (error != 0)
			return (error);
		error = vmx_nested_state_view_field(view, false, i, &expected);
		if (error != 0)
			return (error);
		if (actual.encoding != expected.encoding ||
		    actual.width != expected.width ||
		    actual.value != expected.value)
			return (EPROTO);
	}
	error = vmx_nested_vmcs_region_launched(entry->region,
	    sizeof(entry->region), &registry->capabilities, false, &launched,
	    &epoch);
	if (error != 0)
		return (error);
	if (launched != ((view->flags &
	    VMX_NESTED_STATE_F_CURRENT_LAUNCHED) != 0))
		return (EPROTO);
	error = vmx_nested_vmcs_region_abort_indicator(entry->region,
	    sizeof(entry->region), &registry->capabilities, false,
	    &abort_indicator);
	if (error != 0)
		return (error);
	if (abort_indicator != view->abort_indicator)
		return (EPROTO);
	return (0);
}

static int
nvmxrs_restore(
    struct vmx_nested_vmcs_registry *registry, const void *buffer,
    size_t length, const struct vmx_nested_state_view *current)
{
	struct vmx_nested_vmcs_registry temporary;
	struct vmx_nested_capabilities wire_capabilities;
	struct vmx_nested_field *fields;
	const uint8_t *bytes, *cursor, *end;
	uint64_t capability_signature, epoch, gpa, previous;
	uint32_t abort_indicator, count, field_count, flags, limit;
	size_t maximum, required;
	uint16_t version;
	bool initialized;
	int error;

	if (registry == NULL || buffer == NULL ||
	    length < NVMXRS_HEADER_SIZE)
		return (EINVAL);
	error = vmx_nested_vmcs_registry_validate(registry);
	if (error != 0)
		return (error);
	maximum = NVMXRS_HEADER_SIZE + NVMXRS_CAPABILITIES_SIZE +
	    (size_t)registry->limit * (NVMXRS_ENTRY_SIZE +
	    (size_t)VMX_NESTED_STATE_MAX_FIELDS * NVMXRS_FIELD_SIZE);
	if (length > UINT32_MAX || length > maximum)
		return (E2BIG);
	if (vmx_nested_vmcs_registry_storage_overlaps(registry, buffer,
	    length))
		return (EINVAL);
	bytes = buffer;
	version = le16dec(bytes + 4);
	if (le32dec(bytes) != NVMXRS_MAGIC ||
	    version != NVMXRS_VERSION ||
	    le16dec(bytes + 6) != NVMXRS_HEADER_SIZE ||
	    le32dec(bytes + 8) != length ||
	    le64dec(bytes + NVMXRS_DIGEST_OFFSET) !=
	    nvmxrs_digest(bytes, length))
		return (EPROTO);
	count = le32dec(bytes + 12);
	limit = le32dec(bytes + 16);
	if (le32dec(bytes + 20) != 0 ||
	    le64dec(bytes + 48) != 0 || le64dec(bytes + 56) != 0 ||
	    count > limit || limit == 0 ||
	    limit > VMX_NESTED_VMCS_REGISTRY_LIMIT ||
	    count > registry->limit)
		return (EPROTO);
	error = vmx_nested_capabilities_signature(&registry->capabilities,
	    &capability_signature);
	if (error != 0)
		return (error);
	if (le64dec(bytes + 24) != capability_signature ||
	    le64dec(bytes + 32) != vmx_nested_vmcs_schema_signature())
		return (ENOTSUP);
	if (length < NVMXRS_HEADER_SIZE + NVMXRS_CAPABILITIES_SIZE)
		return (EMSGSIZE);
	error = vmx_nested_capabilities_wire_decode(
	    bytes + NVMXRS_HEADER_SIZE, NVMXRS_CAPABILITIES_SIZE,
	    &wire_capabilities);
	if (error != 0)
		return (error);
	if (!vmx_nested_capabilities_equal(&wire_capabilities,
	    &registry->capabilities))
		return (ENOTSUP);

	memset(&temporary, 0, sizeof(temporary));
	initialized = false;
	error = vmx_nested_vmcs_registry_init(&temporary,
	    &registry->capabilities, registry->limit);
	if (error != 0)
		return (error);
	initialized = true;
	cursor = bytes + NVMXRS_HEADER_SIZE;
	cursor += NVMXRS_CAPABILITIES_SIZE;
	end = bytes + length;
	previous = 0;
	fields = NULL;
	for (uint32_t i = 0; i < count; i++) {
		if ((size_t)(end - cursor) < NVMXRS_ENTRY_SIZE) {
			error = EMSGSIZE;
			goto out;
		}
		gpa = le64dec(cursor);
		epoch = le64dec(cursor + 8);
		field_count = le32dec(cursor + 16);
		abort_indicator = le32dec(cursor + 20);
		flags = le32dec(cursor + 24);
		if (le32dec(cursor + 28) != 0 ||
		    (i != 0 && gpa <= previous) ||
		    (flags & ~NVMXRS_F_LAUNCHED) != 0 ||
		    (((flags & NVMXRS_F_LAUNCHED) == 0) !=
		    (epoch == 0)) ||
		    abort_indicator > 6 ||
		    field_count > VMX_NESTED_STATE_MAX_FIELDS) {
			error = EPROTO;
			goto out;
		}
		cursor += NVMXRS_ENTRY_SIZE;
		required = (size_t)field_count * NVMXRS_FIELD_SIZE;
		if ((size_t)(end - cursor) < required) {
			error = EMSGSIZE;
			goto out;
		}
		fields = nvmxrs_fields_alloc(field_count);
		if (field_count != 0 && fields == NULL) {
			error = ENOMEM;
			goto out;
		}
		for (uint32_t field_index = 0;
		    field_index < field_count; field_index++) {
			const uint8_t *wire = cursor +
			    (size_t)field_index * NVMXRS_FIELD_SIZE;

			if (wire[5] != 0 || le16dec(wire + 6) != 0) {
				error = EPROTO;
				goto out;
			}
			fields[field_index].encoding = le32dec(wire);
			fields[field_index].width = wire[4];
			fields[field_index].value = le64dec(wire + 8);
		}
		error = vmx_nested_vmcs_registry_import_nowait(&temporary, gpa,
		    fields, field_count,
		    (flags & NVMXRS_F_LAUNCHED) != 0, epoch,
		    abort_indicator);
		nvmxrs_fields_free(fields);
		fields = NULL;
		if (error != 0)
			goto out;
		cursor += required;
		previous = gpa;
	}
	if (cursor != end) {
		error = EPROTO;
		goto out;
	}
	error = nvmxrs_current_matches(&temporary, current);
	if (error != 0)
		goto out;
	error = vmx_nested_vmcs_registry_replace(registry, &temporary);
out:
	nvmxrs_fields_free(fields);
	if (initialized) {
		int destroy_error;

		destroy_error = vmx_nested_vmcs_registry_destroy(&temporary);
		if (error == 0 && destroy_error != 0)
			error = EPROTO;
	}
	return (error);
}

int
vmx_nested_vmcs_registry_state_restore(
    struct vmx_nested_vmcs_registry *registry, const void *buffer,
    size_t length)
{

	return (nvmxrs_restore(registry, buffer, length, NULL));
}

int
vmx_nested_vmcs_registry_state_restore_matching(
    struct vmx_nested_vmcs_registry *registry, const void *buffer,
    size_t length, const struct vmx_nested_state_view *current)
{
	size_t shadow_length, vmcs_length;

	if (current == NULL)
		return (EINVAL);
	{
		int error;

		error = vmx_nested_vmcs_registry_validate(registry);
		if (error != 0)
			return (error);
	}
	if (current->vmcs_field_count > VMX_NESTED_STATE_MAX_FIELDS ||
	    current->shadow_field_count > VMX_NESTED_STATE_MAX_FIELDS)
		return (EINVAL);
	vmcs_length = (size_t)current->vmcs_field_count *
	    VMX_NESTED_STATE_FIELD_SIZE;
	shadow_length = (size_t)current->shadow_field_count *
	    VMX_NESTED_STATE_FIELD_SIZE;
	if ((vmcs_length != 0 && current->vmcs_wire == NULL) ||
	    (shadow_length != 0 && current->shadow_wire == NULL) ||
	    vmx_nested_vmcs_registry_storage_overlaps(registry, current,
	    sizeof(*current)) ||
	    vmx_nested_vmcs_registry_storage_overlaps(registry,
	    current->vmcs_wire, vmcs_length) ||
	    vmx_nested_vmcs_registry_storage_overlaps(registry,
	    current->shadow_wire, shadow_length) ||
	    vmx_nested_state_ranges_overlap(buffer, length, current,
	    sizeof(*current)) ||
	    vmx_nested_state_ranges_overlap(buffer, length,
	    current->vmcs_wire, vmcs_length) ||
	    vmx_nested_state_ranges_overlap(buffer, length,
	    current->shadow_wire, shadow_length) ||
	    vmx_nested_state_ranges_overlap(current, sizeof(*current),
	    current->vmcs_wire, vmcs_length) ||
	    vmx_nested_state_ranges_overlap(current, sizeof(*current),
	    current->shadow_wire, shadow_length) ||
	    vmx_nested_state_ranges_overlap(current->vmcs_wire, vmcs_length,
	    current->shadow_wire, shadow_length))
		return (EINVAL);
	return (nvmxrs_restore(registry, buffer, length, current));
}
