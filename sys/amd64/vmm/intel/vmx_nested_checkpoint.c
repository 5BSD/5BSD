/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/endian.h>
#include <sys/errno.h>
#include <sys/queue.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#else
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/systm.h>

static MALLOC_DEFINE(M_NVMX_CHECKPOINT, "nvmx_checkpoint",
    "Nested VMX portable checkpoint scratch storage");
#endif

#include "vmx_nested_caps.h"
#include "vmx_nested_checkpoint.h"
#include "vmx_nested_context.h"
#include "vmx_nested_control_msr.h"
#include "vmx_nested_l2_continuation_state.h"
#include "vmx_nested_link.h"
#include "vmx_nested_state.h"
#include "vmx_nested_state_range.h"
#include "vmx_nested_vmcs.h"
#include "vmx_nested_vmcs12.h"
#include "vmx_nested_vmcs_registry.h"
#include "vmx_nested_vmcs_registry_state.h"
#include "vmx_nested_vmcs_store.h"

#define	NVMXCP_PRIMARY_MTF	(UINT32_C(1) << 27)

#define	NVMXCP_MAGIC		UINT32_C(0x3150434e)	/* "NCP1" */
#define	NVMXCP_VERSION	3U
#define	NVMXCP_L2_CONT_VERSION	2U
#define	NVMXCP_HEADER_SIZE	64U
#define	NVMXCP_DIGEST_OFFSET	40U
#define	NVMXCP_REGISTRY_MAX_SIZE					\
	(NVMXCP_HEADER_SIZE + VMX_NESTED_CAPABILITIES_WIRE_SIZE +	\
	 (size_t)VMX_NESTED_VMCS_REGISTRY_LIMIT *			\
	 (32U + (size_t)VMX_NESTED_STATE_MAX_FIELDS * 16U))
#define	NVMXCP_MAX_SIZE						\
	(NVMXCP_HEADER_SIZE + (size_t)VMX_NESTED_STATE_MAX_SIZE +	\
	 NVMXCP_REGISTRY_MAX_SIZE +					\
	 (size_t)VMX_NESTED_L2_CONT_STATE_MAX_SIZE)

static int nvmxcp_entry(const struct vmx_nested_vmcs_registry *, uint64_t,
	    struct vmx_nested_vmcs_registry_entry **);

static uint64_t
nvmxcp_digest(const uint8_t *bytes, size_t length)
{
	uint64_t digest;

	digest = UINT64_C(14695981039346656037);
	for (size_t i = 0; i < length; i++) {
		uint8_t byte;

		byte = i >= NVMXCP_DIGEST_OFFSET &&
		    i < NVMXCP_DIGEST_OFFSET + sizeof(uint64_t) ?
		    0 : bytes[i];
		digest ^= byte;
		digest *= UINT64_C(1099511628211);
	}
	return (digest);
}

static int
nvmxcp_section_end(uint32_t offset, uint32_t section_length, size_t capacity,
    size_t *end)
{
	size_t start;

	if (end == NULL || (uint64_t)offset > (uint64_t)SIZE_MAX ||
	    (uint64_t)section_length > (uint64_t)SIZE_MAX)
		return (EPROTO);
	start = (size_t)offset;
	if (start > capacity ||
	    (size_t)section_length > capacity - start)
		return (EPROTO);
	*end = start + (size_t)section_length;
	return (0);
}

static bool
nvmxcp_state_overlap(const struct vmx_nested_state *state, const void *buffer,
    size_t length)
{

	if (state == NULL)
		return (false);
	if (vmx_nested_state_ranges_overlap(buffer, length, state,
	    sizeof(*state)))
		return (true);
	/*
	 * Callers use this predicate before the state-size validator.  Do not
	 * multiply hostile wire-sized counts until they are known to fit the
	 * architectural field bound and, consequently, host size_t.
	 */
	if (state->vmcs_field_count > VMX_NESTED_STATE_MAX_FIELDS ||
	    state->shadow_field_count > VMX_NESTED_STATE_MAX_FIELDS)
		return (true);
	return (
	    vmx_nested_state_ranges_overlap(buffer, length, state->vmcs_fields,
	    (size_t)state->vmcs_field_count * sizeof(*state->vmcs_fields)) ||
	    vmx_nested_state_ranges_overlap(buffer, length, state->shadow_fields,
	    (size_t)state->shadow_field_count *
	    sizeof(*state->shadow_fields)));
}

static bool
nvmxcp_registry_overlap(const struct vmx_nested_vmcs_registry *registry,
    const void *buffer, size_t length)
{

	return (vmx_nested_vmcs_registry_storage_overlaps(registry, buffer,
	    length));
}

static int
nvmxcp_sizes(const struct vmx_nested_state *state,
    const struct vmx_nested_vmcs_registry *registry, size_t *state_size,
    size_t *registry_size, size_t *total)
{
	size_t encoded, reg_size;
	int error;

	if (state == NULL || registry == NULL || state_size == NULL ||
	    registry_size == NULL || total == NULL)
		return (EINVAL);
	error = vmx_nested_state_size(state, &encoded);
	if (error != 0)
		return (error);
	error = vmx_nested_vmcs_registry_state_size(registry, &reg_size);
	if (error != 0)
		return (error);
	if (encoded > UINT32_MAX || reg_size > UINT32_MAX ||
	    encoded > SIZE_MAX - NVMXCP_HEADER_SIZE ||
	    reg_size > SIZE_MAX - NVMXCP_HEADER_SIZE - encoded ||
	    NVMXCP_HEADER_SIZE + encoded + reg_size > UINT32_MAX)
		return (EOVERFLOW);
	*state_size = encoded;
	*registry_size = reg_size;
	*total = NVMXCP_HEADER_SIZE + encoded + reg_size;
	return (0);
}

int
vmx_nested_checkpoint_size(const struct vmx_nested_state *state,
    const struct vmx_nested_vmcs_registry *registry, size_t *size)
{
	size_t registry_size, state_size, total;
	int error;

	if (size == NULL)
		return (EINVAL);
	if (nvmxcp_state_overlap(state, size, sizeof(*size)) ||
	    vmx_nested_vmcs_registry_storage_overlaps(registry, size,
	    sizeof(*size)))
		return (EINVAL);
	error = nvmxcp_sizes(state, registry, &state_size, &registry_size,
	    &total);
	if (error == 0)
		*size = total;
	return (error);
}

int
vmx_nested_checkpoint_encode(const struct vmx_nested_state *state,
    const struct vmx_nested_vmcs_registry *registry, void *buffer,
    size_t capacity, size_t *written)
{
	uint8_t *bytes;
	size_t registry_size, registry_written, state_size, state_written, total;
	int error;

	if (buffer == NULL || written == NULL)
		return (EINVAL);
	error = nvmxcp_sizes(state, registry, &state_size, &registry_size,
	    &total);
	if (error != 0)
		return (error);
	if (vmx_nested_state_ranges_overlap(buffer, total, written,
	    sizeof(*written)) ||
	    nvmxcp_state_overlap(state, buffer, total) ||
	    nvmxcp_state_overlap(state, written, sizeof(*written)) ||
	    vmx_nested_vmcs_registry_storage_overlaps(registry, buffer, total) ||
	    vmx_nested_vmcs_registry_storage_overlaps(registry, written,
	    sizeof(*written)))
		return (EINVAL);
	*written = 0;
	if (capacity < total)
		return (ENOSPC);

	bytes = buffer;
	memset(bytes, 0, total);
	error = vmx_nested_state_encode(state, bytes + NVMXCP_HEADER_SIZE,
	    state_size, &state_written);
	if (error != 0 || state_written != state_size)
		return (error != 0 ? error : EPROTO);
	error = vmx_nested_vmcs_registry_state_encode(registry,
	    bytes + NVMXCP_HEADER_SIZE + state_size, registry_size,
	    &registry_written);
	if (error != 0 || registry_written != registry_size)
		return (error != 0 ? error : EPROTO);

	le32enc(bytes, NVMXCP_MAGIC);
	le16enc(bytes + 4, NVMXCP_VERSION);
	le16enc(bytes + 6, NVMXCP_HEADER_SIZE);
	le32enc(bytes + 8, (uint32_t)total);
	le32enc(bytes + 16, NVMXCP_HEADER_SIZE);
	le32enc(bytes + 20, (uint32_t)state_size);
	le32enc(bytes + 24, NVMXCP_HEADER_SIZE + (uint32_t)state_size);
	le32enc(bytes + 28, (uint32_t)registry_size);
	le64enc(bytes + NVMXCP_DIGEST_OFFSET,
	    nvmxcp_digest(bytes, total));
	*written = total;
	return (0);
}

static int
nvmxcp_active_sizes(const struct vmx_nested_state *state,
    const struct vmx_nested_vmcs_registry *registry,
    const struct vmx_nested_l0_continuation *continuation,
    const struct vmx_nested_l2_portable_state *portable, size_t *state_size,
    size_t *registry_size, size_t *total)
{
	struct vmx_nested_l0_continuation_record record;
	struct vmx_nested_vmcs_registry_entry *entry;
	uint64_t launched_epoch;
	size_t base;
	bool launched;
	int error;

	if (continuation == NULL || portable == NULL)
		return (EINVAL);
	error = nvmxcp_sizes(state, registry, state_size, registry_size, &base);
	if (error != 0)
		return (error);
	error = vmx_nested_l0_continuation_export(continuation, &record);
	if (error != 0)
		return (error);
	error = vmx_nested_l2_portable_validate(portable);
	if (error != 0)
		return (error);
	if ((state->flags & (VMX_NESTED_STATE_F_VMXON |
	    VMX_NESTED_STATE_F_GUEST_MODE |
	    VMX_NESTED_STATE_F_CURRENT_LAUNCHED)) !=
	    (VMX_NESTED_STATE_F_VMXON |
	    VMX_NESTED_STATE_F_GUEST_MODE |
	    VMX_NESTED_STATE_F_CURRENT_LAUNCHED) ||
	    state->current_vmcs_gpa != portable->id.vmcs12_gpa ||
	    state->capability_signature != portable->capability_signature ||
	    !vmx_nested_vmcs02_id_equal(&record.id, &portable->id) ||
	    record.portable_generation != portable->portable_generation)
		return (EINVAL);
	error = nvmxcp_entry(registry, state->current_vmcs_gpa, &entry);
	if (error != 0)
		return (error);
	if (entry == NULL)
		return (ESTALE);
	error = vmx_nested_vmcs_region_launched(entry->region,
	    sizeof(entry->region), &registry->capabilities, false,
	    &launched, &launched_epoch);
	if (error != 0)
		return (error);
	if (!launched || launched_epoch != portable->id.execution_epoch)
		return (ESTALE);
	if (base > SIZE_MAX - VMX_NESTED_L2_CONT_STATE_SIZE ||
	    base + VMX_NESTED_L2_CONT_STATE_SIZE > UINT32_MAX)
		return (EOVERFLOW);
	*total = base + VMX_NESTED_L2_CONT_STATE_SIZE;
	return (0);
}

int
vmx_nested_checkpoint_active_size(const struct vmx_nested_state *state,
    const struct vmx_nested_vmcs_registry *registry,
    const struct vmx_nested_l0_continuation *continuation,
    const struct vmx_nested_l2_portable_state *portable, size_t *size)
{
	size_t registry_size, state_size, total;
	int error;

	if (size == NULL ||
	    nvmxcp_state_overlap(state, size, sizeof(*size)) ||
	    nvmxcp_registry_overlap(registry, size, sizeof(*size)) ||
	    vmx_nested_state_ranges_overlap(size, sizeof(*size), continuation,
	    sizeof(*continuation)) ||
	    vmx_nested_state_ranges_overlap(size, sizeof(*size), portable,
	    sizeof(*portable)))
		return (EINVAL);
	error = nvmxcp_active_sizes(state, registry, continuation, portable,
	    &state_size, &registry_size, &total);
	if (error == 0)
		*size = total;
	return (error);
}

int
vmx_nested_checkpoint_active_encode(const struct vmx_nested_state *state,
    const struct vmx_nested_vmcs_registry *registry,
    const struct vmx_nested_l0_continuation *continuation,
    const struct vmx_nested_l2_portable_state *portable, void *buffer,
    size_t capacity, size_t *written)
{
	uint8_t *bytes;
	size_t l2_written, registry_size, registry_written, state_size;
	size_t state_written, total;
	uint32_t registry_offset, l2_offset;
	int error;

	if (buffer == NULL || written == NULL)
		return (EINVAL);
	error = nvmxcp_active_sizes(state, registry, continuation, portable,
	    &state_size, &registry_size, &total);
	if (error != 0)
		return (error);
	if (vmx_nested_state_ranges_overlap(buffer, total, written,
	    sizeof(*written)) ||
	    nvmxcp_state_overlap(state, buffer, total) ||
	    nvmxcp_state_overlap(state, written, sizeof(*written)) ||
	    nvmxcp_registry_overlap(registry, buffer, total) ||
	    nvmxcp_registry_overlap(registry, written, sizeof(*written)) ||
	    vmx_nested_state_ranges_overlap(buffer, total, continuation,
	    sizeof(*continuation)) ||
	    vmx_nested_state_ranges_overlap(buffer, total, portable,
	    sizeof(*portable)) ||
	    vmx_nested_state_ranges_overlap(written, sizeof(*written), continuation,
	    sizeof(*continuation)) ||
	    vmx_nested_state_ranges_overlap(written, sizeof(*written), portable,
	    sizeof(*portable)))
		return (EINVAL);
	*written = 0;
	if (capacity < total)
		return (ENOSPC);

	bytes = buffer;
	memset(bytes, 0, total);
	error = vmx_nested_state_encode(state, bytes + NVMXCP_HEADER_SIZE,
	    state_size, &state_written);
	if (error != 0 || state_written != state_size)
		return (error != 0 ? error : EPROTO);
	registry_offset = NVMXCP_HEADER_SIZE + (uint32_t)state_size;
	error = vmx_nested_vmcs_registry_state_encode(registry,
	    bytes + registry_offset, registry_size, &registry_written);
	if (error != 0 || registry_written != registry_size)
		return (error != 0 ? error : EPROTO);
	l2_offset = registry_offset + (uint32_t)registry_size;
	error = vmx_nested_l2_continuation_state_encode(continuation,
	    portable, bytes + l2_offset, VMX_NESTED_L2_CONT_STATE_SIZE,
	    &l2_written);
	if (error != 0 || l2_written != VMX_NESTED_L2_CONT_STATE_SIZE)
		return (error != 0 ? error : EPROTO);

	le32enc(bytes, NVMXCP_MAGIC);
	le16enc(bytes + 4, NVMXCP_VERSION);
	le16enc(bytes + 6, NVMXCP_HEADER_SIZE);
	le32enc(bytes + 8, (uint32_t)total);
	le32enc(bytes + 16, NVMXCP_HEADER_SIZE);
	le32enc(bytes + 20, (uint32_t)state_size);
	le32enc(bytes + 24, registry_offset);
	le32enc(bytes + 28, (uint32_t)registry_size);
	le32enc(bytes + 32, l2_offset);
	le32enc(bytes + 36, VMX_NESTED_L2_CONT_STATE_SIZE);
	le64enc(bytes + NVMXCP_DIGEST_OFFSET, nvmxcp_digest(bytes, total));
	*written = total;
	return (0);
}

int
vmx_nested_checkpoint_decode(const void *buffer, size_t length,
    struct vmx_nested_checkpoint_view *view)
{
	struct vmx_nested_checkpoint_view candidate;
	struct vmx_nested_l2_continuation_state l2;
	const uint8_t *bytes;
	uint32_t l2_length, l2_offset, registry_length, registry_offset;
	uint32_t state_length, state_offset, version;
	size_t l2_end, registry_end, state_end;
	int error;

	if (buffer == NULL || view == NULL)
		return (EINVAL);
	if (length < NVMXCP_HEADER_SIZE)
		return (EMSGSIZE);
	if (length > UINT32_MAX || length > NVMXCP_MAX_SIZE)
		return (E2BIG);
	if (vmx_nested_state_ranges_overlap(buffer, length, view, sizeof(*view)))
		return (EINVAL);
	bytes = buffer;
	version = le16dec(bytes + 4);
	if (le32dec(bytes) != NVMXCP_MAGIC ||
	    version != NVMXCP_VERSION ||
	    le16dec(bytes + 6) != NVMXCP_HEADER_SIZE ||
	    le32dec(bytes + 8) != length ||
	    le32dec(bytes + 12) != 0 ||
	    le64dec(bytes + 48) != 0 || le64dec(bytes + 56) != 0 ||
	    le64dec(bytes + NVMXCP_DIGEST_OFFSET) !=
	    nvmxcp_digest(bytes, length))
		return (EPROTO);
	state_offset = le32dec(bytes + 16);
	state_length = le32dec(bytes + 20);
	registry_offset = le32dec(bytes + 24);
	registry_length = le32dec(bytes + 28);
	l2_offset = le32dec(bytes + 32);
	l2_length = le32dec(bytes + 36);
	error = nvmxcp_section_end(state_offset, state_length, length,
	    &state_end);
	if (error != 0)
		return (error);
	error = nvmxcp_section_end(registry_offset, registry_length, length,
	    &registry_end);
	if (error != 0)
		return (error);
	if (state_offset != NVMXCP_HEADER_SIZE ||
	    state_length < VMX_NESTED_STATE_HEADER_SIZE ||
	    state_length > VMX_NESTED_STATE_MAX_SIZE ||
	    registry_offset != state_end || registry_length == 0)
		return (EPROTO);
	if (l2_offset == 0 && l2_length == 0) {
		if (l2_offset != 0 || l2_length != 0 ||
			    registry_end != length)
				return (EPROTO);
	} else {
		error = nvmxcp_section_end(l2_offset, l2_length, length,
		    &l2_end);
		if (error != 0)
			return (error);
		if (l2_offset != registry_end ||
		    l2_length != VMX_NESTED_L2_CONT_STATE_SIZE ||
		    l2_end != length)
			return (EPROTO);
	}

	memset(&candidate, 0, sizeof(candidate));
	error = vmx_nested_state_decode(bytes + state_offset, state_length,
	    &candidate.state);
	if (error != 0)
		return (error);
	candidate.registry_wire = bytes + registry_offset;
	candidate.registry_length = registry_length;
	if (l2_offset != 0) {
		if (le16dec(bytes + l2_offset + 4) !=
		    NVMXCP_L2_CONT_VERSION)
			return (EPROTO);
		error = vmx_nested_l2_continuation_state_decode(
		    bytes + l2_offset, l2_length, &l2);
		if (error != 0 ||
		    (candidate.state.flags & (VMX_NESTED_STATE_F_VMXON |
		    VMX_NESTED_STATE_F_GUEST_MODE |
		    VMX_NESTED_STATE_F_CURRENT_LAUNCHED)) !=
		    (VMX_NESTED_STATE_F_VMXON |
		    VMX_NESTED_STATE_F_GUEST_MODE |
		    VMX_NESTED_STATE_F_CURRENT_LAUNCHED) ||
		    candidate.state.current_vmcs_gpa !=
		    l2.portable.id.vmcs12_gpa ||
		    candidate.state.capability_signature !=
		    l2.portable.capability_signature)
			return (EPROTO);
		candidate.l2_wire = bytes + l2_offset;
		candidate.l2_length = l2_length;
	}
	*view = candidate;
	return (0);
}

int
vmx_nested_checkpoint_restore(struct vmx_nested_vmcs_registry *registry,
    const struct vmx_nested_capabilities *capabilities, const void *buffer,
    size_t length, struct vmx_nested_checkpoint_view *view)
{
	struct vmx_nested_checkpoint_view candidate;
	int error;

	if (registry == NULL || capabilities == NULL || view == NULL)
		return (EINVAL);
	/*
	 * A decoded view borrows its section pointers from buffer.  Publishing
	 * the view into that same wire image would invalidate those pointers
	 * after the registry transaction had already committed.  Reject the
	 * overlap before decoding or replacing any live registry state.
	 */
	if (vmx_nested_state_ranges_overlap(view, sizeof(*view), buffer,
	    length))
		return (EINVAL);
	if (!registry->initialized ||
	    !vmx_nested_capabilities_equal(&registry->capabilities,
	    capabilities))
		return (EINVAL);
	if (nvmxcp_registry_overlap(registry, buffer, length) ||
	    nvmxcp_registry_overlap(registry, view, sizeof(*view)) ||
	    vmx_nested_state_ranges_overlap(view, sizeof(*view), capabilities,
	    sizeof(*capabilities)))
		return (EINVAL);
	error = vmx_nested_checkpoint_decode(buffer, length, &candidate);
	if (error != 0)
		return (error);
	error = vmx_nested_state_destination_validate(&candidate.state,
	    capabilities);
	if (error != 0)
		return (error);
	error = vmx_nested_vmcs_registry_state_restore_matching(registry,
	    candidate.registry_wire, candidate.registry_length,
	    &candidate.state);
	if (error != 0)
		return (error);
	*view = candidate;
	return (0);
}

static int
nvmxcp_owned_entry(const struct vmx_nested_vmcs_registry *registry,
    uint64_t gpa, uint32_t owner,
    struct vmx_nested_vmcs_registry_entry **result)
{
	struct vmx_nested_vmcs_registry_entry *entry;
	bool owner_active;
	int error;

	if (result == NULL)
		return (EINVAL);
	*result = NULL;
	error = vmx_nested_vmcs_registry_owner_active(registry, owner,
	    &owner_active);
	if (error != 0)
		return (error);
	if (!owner_active)
		return (0);
	error = nvmxcp_entry(registry, gpa, &entry);
	if (error != 0)
		return (error);
	if (entry != NULL && entry->owner == owner)
		*result = entry;
	return (0);
}

static int
nvmxcp_entry(const struct vmx_nested_vmcs_registry *registry, uint64_t gpa,
    struct vmx_nested_vmcs_registry_entry **result)
{
	struct vmx_nested_vmcs_registry_entry *entry, *result_entry;
	uint32_t bucket;
	int error;

	if (result == NULL)
		return (EINVAL);
	*result = NULL;
	error = vmx_nested_vmcs_registry_validate(registry);
	if (error != 0)
		return (error);
	bucket = (gpa >> VMX_NESTED_VMCS_REGION_SHIFT) &
	    (VMX_NESTED_VMCS_REGISTRY_BUCKETS - 1);
	result_entry = NULL;
	LIST_FOREACH(entry, &registry->entries[bucket], link) {
		if (entry->gpa == gpa) {
			if (result_entry != NULL)
				return (EPROTO);
			result_entry = entry;
		}
	}
	*result = result_entry;
	return (0);
}

static int
nvmxcp_owner_present(const struct vmx_nested_vmcs_registry *registry,
    uint32_t owner, bool *present)
{
	if (present == NULL)
		return (EINVAL);
	*present = false;
	return (vmx_nested_vmcs_registry_owner_active(registry, owner,
	    present));
}

static struct vmx_nested_field *
nvmxcp_fields_alloc(uint32_t count)
{

	if (count == 0)
		return (NULL);
#ifdef _KERNEL
	return (mallocarray(count, sizeof(struct vmx_nested_field),
	    M_NVMX_CHECKPOINT, M_NOWAIT | M_ZERO));
#else
	return (calloc(count, sizeof(struct vmx_nested_field)));
#endif
}

static void
nvmxcp_fields_free(struct vmx_nested_field *fields, uint32_t count)
{

	if (fields == NULL)
		return;
	explicit_bzero(fields, (size_t)count * sizeof(*fields));
#ifdef _KERNEL
	free(fields, M_NVMX_CHECKPOINT);
#else
	free(fields);
#endif
}

int
vmx_nested_checkpoint_capture(const struct vmx_nested_context *context,
    const struct vmx_nested_control_msr_state *control,
    const struct vmx_nested_vmcs_registry *registry, uint32_t owner,
    struct vmx_nested_field *fields, uint32_t capacity,
    struct vmx_nested_state *state)
{
	struct vmx_nested_vmcs_registry_entry *entry;
	struct vmx_nested_field *scratch;
	struct vmx_nested_state candidate;
	uint64_t capability_signature, launched_epoch;
	size_t ignored_size;
	uint32_t field_count;
	bool launched, owner_active;
	int error;

	scratch = NULL;
	if (context == NULL || control == NULL || registry == NULL ||
	    state == NULL || owner == VMX_NESTED_VMCS_NO_OWNER ||
	    capacity > VMX_NESTED_STATE_MAX_FIELDS ||
	    (capacity != 0 && fields == NULL) ||
	    vmx_nested_state_ranges_overlap(state, sizeof(*state), context,
	    sizeof(*context)) ||
	    vmx_nested_state_ranges_overlap(state, sizeof(*state), control,
	    sizeof(*control)) ||
	    vmx_nested_state_ranges_overlap(fields,
	    (size_t)capacity * sizeof(*fields), context, sizeof(*context)) ||
	    vmx_nested_state_ranges_overlap(fields,
	    (size_t)capacity * sizeof(*fields), control, sizeof(*control)) ||
	    vmx_nested_state_ranges_overlap(fields,
	    (size_t)capacity * sizeof(*fields), state, sizeof(*state)))
		return (EINVAL);
	error = vmx_nested_vmcs_registry_validate(registry);
	if (error != 0)
		return (error);
	if (nvmxcp_registry_overlap(registry, state, sizeof(*state)) ||
	    nvmxcp_registry_overlap(registry, fields,
	    (size_t)capacity * sizeof(*fields)))
		return (EINVAL);
	error = vmx_nested_context_quiesce(context);
	if (error != 0)
		return (error);
	if (context->phase != VMX_NESTED_CONTEXT_ROOT &&
	    context->phase != VMX_NESTED_CONTEXT_ABORTED)
		return (ENOTSUP);
	error = vmx_nested_control_msr_validate(control);
	if (error != 0)
		return (error);

	memset(&candidate, 0, sizeof(candidate));
	candidate.feature_control = control->feature_control;
	candidate.vmxon_gpa = VMX_NESTED_STATE_INVALID_GPA;
	candidate.current_vmcs_gpa = VMX_NESTED_STATE_INVALID_GPA;
	if (!context->machine.vmxon) {
		error = nvmxcp_owner_present(registry, owner, &owner_active);
		if (error != 0)
			return (error);
		if (owner_active)
			return (EPROTO);
		error = vmx_nested_state_size(&candidate, &ignored_size);
		if (error != 0)
			return (error);
		*state = candidate;
		return (0);
	}
	error = vmx_nested_capabilities_signature(&registry->capabilities,
	    &capability_signature);
	if (error != 0)
		return (error);
	candidate.flags = VMX_NESTED_STATE_F_VMXON;
	candidate.vmxon_gpa = context->machine.vmxon_gpa;
	candidate.current_vmcs_gpa = context->machine.current_vmcs_gpa;
	candidate.capability_signature = capability_signature;
	candidate.schema_signature = vmx_nested_vmcs_schema_signature();
	candidate.vmx_epoch = context->machine.epoch;
	if (candidate.current_vmcs_gpa == VMX_NESTED_STATE_INVALID_GPA) {
		error = nvmxcp_owner_present(registry, owner, &owner_active);
		if (error != 0)
			return (error);
		if (owner_active ||
		    context->phase == VMX_NESTED_CONTEXT_ABORTED ||
		    context->abort_indicator != 0)
			return (EPROTO);
		error = vmx_nested_state_size(&candidate, &ignored_size);
		if (error != 0)
			return (error);
		*state = candidate;
		return (0);
	}
	error = nvmxcp_owned_entry(registry, candidate.current_vmcs_gpa,
	    owner, &entry);
	if (error != 0)
		return (error);
	if (entry == NULL)
		return (ESTALE);
	error = vmx_nested_vmcs_region_field_count(entry->region,
	    sizeof(entry->region), &registry->capabilities, false,
	    &field_count);
	if (error != 0)
		return (error);
	if (field_count > capacity)
		return (ENOSPC);
	scratch = nvmxcp_fields_alloc(field_count);
	if (field_count != 0 && scratch == NULL)
		return (ENOMEM);
	for (uint32_t i = 0; i < field_count; i++) {
		error = vmx_nested_vmcs_region_field(entry->region,
		    sizeof(entry->region), &registry->capabilities, false, i,
		    &scratch[i]);
		if (error != 0)
			goto out;
	}
	error = vmx_nested_vmcs_region_launched(entry->region,
	    sizeof(entry->region), &registry->capabilities, false, &launched,
	    &launched_epoch);
	if (error != 0)
		goto out;
	error = vmx_nested_vmcs_region_abort_indicator(entry->region,
	    sizeof(entry->region), &registry->capabilities, false,
	    &candidate.abort_indicator);
	if (error != 0)
		goto out;
	if (launched)
		candidate.flags |= VMX_NESTED_STATE_F_CURRENT_LAUNCHED;
	if ((context->phase == VMX_NESTED_CONTEXT_ABORTED) !=
	    (candidate.abort_indicator != 0) ||
	    context->abort_indicator != candidate.abort_indicator) {
		error = EPROTO;
		goto out;
	}
	candidate.revision_id = registry->capabilities.revision_id;
	candidate.vmcs_fields = scratch;
	candidate.vmcs_field_count = field_count;
	error = vmx_nested_state_size(&candidate, &ignored_size);
	if (error != 0)
		goto out;
	if (field_count != 0)
		memcpy(fields, scratch, (size_t)field_count * sizeof(*fields));
	candidate.vmcs_fields = fields;
	*state = candidate;
out:
	nvmxcp_fields_free(scratch, field_count);
	return (error);
}

int
vmx_nested_checkpoint_active_capture(
    const struct vmx_nested_context *context,
    const struct vmx_nested_control_msr_state *control,
    const struct vmx_nested_l0_continuation *continuation,
    const struct vmx_nested_entry_runtime *runtime,
    const struct vmx_nested_l2_portable_state *portable,
    const struct vmx_nested_vmcs_registry *registry, uint32_t owner,
    struct vmx_nested_field *fields, uint32_t capacity,
    const struct vmx_nested_field *shadow_fields, uint32_t shadow_count,
    struct vmx_nested_state *state)
{
	struct vmx_nested_vmcs_registry_entry *entry;
	struct vmx_nested_field *scratch;
	struct vmx_nested_state candidate;
	struct vmx_nested_vmcs12_snapshot snapshot;
	uint64_t capability_signature, launched_epoch;
	size_t ignored_size;
	uint32_t field_count;
	bool launched, shadow_present, shadow_required;
	int error;

	scratch = NULL;
	field_count = 0;
	if (context == NULL || control == NULL || continuation == NULL ||
	    runtime == NULL || portable == NULL || registry == NULL ||
	    state == NULL || owner == VMX_NESTED_VMCS_NO_OWNER ||
	    capacity > VMX_NESTED_STATE_MAX_FIELDS ||
	    shadow_count > VMX_NESTED_STATE_MAX_FIELDS ||
	    (capacity != 0 && fields == NULL) ||
	    (shadow_count != 0 && shadow_fields == NULL) ||
	    vmx_nested_state_ranges_overlap(state, sizeof(*state), context,
	    sizeof(*context)) ||
	    vmx_nested_state_ranges_overlap(state, sizeof(*state), control,
	    sizeof(*control)) ||
	    vmx_nested_state_ranges_overlap(state, sizeof(*state), continuation,
	    sizeof(*continuation)) ||
	    vmx_nested_state_ranges_overlap(state, sizeof(*state), runtime,
	    sizeof(*runtime)) ||
	    vmx_nested_state_ranges_overlap(state, sizeof(*state), portable,
	    sizeof(*portable)) ||
	    vmx_nested_state_ranges_overlap(state, sizeof(*state), shadow_fields,
	    (size_t)shadow_count * sizeof(*shadow_fields)) ||
	    vmx_nested_state_ranges_overlap(fields,
	    (size_t)capacity * sizeof(*fields), shadow_fields,
	    (size_t)shadow_count * sizeof(*shadow_fields)) ||
	    vmx_nested_state_ranges_overlap(fields,
	    (size_t)capacity * sizeof(*fields), context, sizeof(*context)) ||
	    vmx_nested_state_ranges_overlap(fields,
	    (size_t)capacity * sizeof(*fields), control, sizeof(*control)) ||
	    vmx_nested_state_ranges_overlap(fields,
	    (size_t)capacity * sizeof(*fields), continuation,
	    sizeof(*continuation)) ||
	    vmx_nested_state_ranges_overlap(fields,
	    (size_t)capacity * sizeof(*fields), runtime, sizeof(*runtime)) ||
	    vmx_nested_state_ranges_overlap(fields,
	    (size_t)capacity * sizeof(*fields), portable,
	    sizeof(*portable)) ||
	    vmx_nested_state_ranges_overlap(fields,
	    (size_t)capacity * sizeof(*fields), state, sizeof(*state)))
		return (EINVAL);
	error = vmx_nested_vmcs_registry_validate(registry);
	if (error != 0)
		return (error);
	if (nvmxcp_registry_overlap(registry, state, sizeof(*state)) ||
	    nvmxcp_registry_overlap(registry, fields,
	    (size_t)capacity * sizeof(*fields)) ||
	    nvmxcp_registry_overlap(registry, shadow_fields,
	    (size_t)shadow_count * sizeof(*shadow_fields)))
		return (EINVAL);
	error = vmx_nested_l0_continuation_quiesce_context(context,
	    continuation, runtime, portable);
	if (error != 0)
		return (error);
	error = vmx_nested_control_msr_validate(control);
	if (error != 0)
		return (error);
	if (!context->machine.vmxon ||
	    context->machine.current_vmcs_gpa != portable->id.vmcs12_gpa ||
	    context->abort_indicator != 0)
		return (EPROTO);
	error = nvmxcp_owned_entry(registry,
	    context->machine.current_vmcs_gpa, owner, &entry);
	if (error != 0)
		return (error);
	if (entry == NULL)
		return (ESTALE);
	error = vmx_nested_vmcs_region_launched(entry->region,
	    sizeof(entry->region), &registry->capabilities, false, &launched,
	    &launched_epoch);
	if (error != 0)
		return (error);
	if (!launched || launched_epoch != portable->id.execution_epoch)
		return (ESTALE);
	error = vmx_nested_vmcs12_snapshot_region(entry->region,
	    sizeof(entry->region), &registry->capabilities,
	    context->machine.current_vmcs_gpa, false, &snapshot);
	if (error != 0)
		return (error);
	if (portable->mtf_pending &&
	    (snapshot.controls.primary & NVMXCP_PRIMARY_MTF) == 0)
		return (ESTALE);
	/*
	 * Intel permits a link pointer while VMCS shadowing is disabled.  Such
	 * a link is validated at entry but is not a separately consumed part of
	 * an ordinary, non-SMM L2 execution image.  Preserve a separate image
	 * only for an exposed mode which can consume it.  A non-NULL pointer
	 * still represents an empty-but-present image.
	 */
	shadow_present = shadow_fields != NULL;
	shadow_required = vmx_nested_link_state_required(
	    snapshot.controls.primary, snapshot.controls.secondary,
	    snapshot.controls.vmentry, snapshot.controls.in_smm,
	    snapshot.guest_arch.in_smm, snapshot.link_pointer);
	if (shadow_required != shadow_present)
		return (ESTALE);
	error = vmx_nested_vmcs_region_field_count(entry->region,
	    sizeof(entry->region), &registry->capabilities, false,
	    &field_count);
	if (error != 0)
		return (error);
	if (field_count > capacity)
		return (ENOSPC);
	scratch = nvmxcp_fields_alloc(field_count);
	if (field_count != 0 && scratch == NULL)
		return (ENOMEM);
	for (uint32_t i = 0; i < field_count; i++) {
		error = vmx_nested_vmcs_region_field(entry->region,
		    sizeof(entry->region), &registry->capabilities, false, i,
		    &scratch[i]);
		if (error != 0)
			goto out;
	}
	error = vmx_nested_capabilities_signature(&registry->capabilities,
	    &capability_signature);
	if (error != 0)
		goto out;
	if (capability_signature != portable->capability_signature) {
		error = ESTALE;
		goto out;
	}

	memset(&candidate, 0, sizeof(candidate));
	candidate.flags = VMX_NESTED_STATE_F_VMXON |
	    VMX_NESTED_STATE_F_GUEST_MODE |
	    VMX_NESTED_STATE_F_CURRENT_LAUNCHED;
	if (portable->mtf_pending)
		candidate.flags |= VMX_NESTED_STATE_F_MTF_PENDING;
	if (shadow_present)
		candidate.flags |= VMX_NESTED_STATE_F_SHADOW_VALID;
	candidate.vmxon_gpa = context->machine.vmxon_gpa;
	candidate.current_vmcs_gpa =
	    context->machine.current_vmcs_gpa;
	candidate.capability_signature = capability_signature;
	candidate.schema_signature = vmx_nested_vmcs_schema_signature();
	candidate.vmx_epoch = context->machine.epoch;
	candidate.feature_control = control->feature_control;
	candidate.revision_id = registry->capabilities.revision_id;
	candidate.vmcs_fields = scratch;
	candidate.vmcs_field_count = field_count;
	candidate.shadow_fields = shadow_fields;
	candidate.shadow_field_count = shadow_count;
	error = vmx_nested_state_size(&candidate, &ignored_size);
	if (error != 0)
		goto out;
	if (field_count != 0)
		memcpy(fields, scratch, (size_t)field_count * sizeof(*fields));
	candidate.vmcs_fields = fields;
	*state = candidate;
out:
	nvmxcp_fields_free(scratch, field_count);
	return (error);
}

static int
nvmxcp_restored_current_validate(
    const struct vmx_nested_vmcs_registry *registry,
    const struct vmx_nested_state_view *state)
{
	struct vmx_nested_vmcs_registry_entry *entry;
	struct vmx_nested_field actual, expected;
	uint64_t launched_epoch;
	uint32_t abort_indicator, field_count;
	bool launched;
	int error;

	if (state->current_vmcs_gpa == VMX_NESTED_STATE_INVALID_GPA)
		return (state->vmcs_field_count == 0 ? 0 : EPROTO);
	error = nvmxcp_entry(registry, state->current_vmcs_gpa, &entry);
	if (error != 0)
		return (error);
	if (entry == NULL || entry->owner != VMX_NESTED_VMCS_NO_OWNER)
		return (ESTALE);
	error = vmx_nested_vmcs_region_field_count(entry->region,
	    sizeof(entry->region), &registry->capabilities, false,
	    &field_count);
	if (error != 0 || field_count != state->vmcs_field_count)
		return (error != 0 ? error : EPROTO);
	for (uint32_t i = 0; i < field_count; i++) {
		error = vmx_nested_vmcs_region_field(entry->region,
		    sizeof(entry->region), &registry->capabilities, false, i,
		    &actual);
		if (error != 0)
			return (error);
		error = vmx_nested_state_view_field(state, false, i,
		    &expected);
		if (error != 0)
			return (error);
		if (actual.encoding != expected.encoding ||
		    actual.width != expected.width ||
		    actual.value != expected.value)
			return (EPROTO);
	}
	error = vmx_nested_vmcs_region_launched(entry->region,
	    sizeof(entry->region), &registry->capabilities, false, &launched,
	    &launched_epoch);
	if (error != 0)
		return (error);
	if (launched != ((state->flags &
	    VMX_NESTED_STATE_F_CURRENT_LAUNCHED) != 0))
		return (EPROTO);
	error = vmx_nested_vmcs_region_abort_indicator(entry->region,
	    sizeof(entry->region), &registry->capabilities, false,
	    &abort_indicator);
	if (error != 0)
		return (error);
	return (abort_indicator == state->abort_indicator ? 0 : EPROTO);
}

static bool
nvmxcp_view_output_overlap(const struct vmx_nested_checkpoint_view *view,
    const void *output, size_t output_length)
{

	return (vmx_nested_state_ranges_overlap(output, output_length, view,
	    sizeof(*view)) ||
	    vmx_nested_state_ranges_overlap(output, output_length,
	    view->state.vmcs_wire,
	    (size_t)view->state.vmcs_field_count *
	    VMX_NESTED_STATE_FIELD_SIZE) ||
	    vmx_nested_state_ranges_overlap(output, output_length,
	    view->state.shadow_wire,
	    (size_t)view->state.shadow_field_count *
	    VMX_NESTED_STATE_FIELD_SIZE) ||
	    vmx_nested_state_ranges_overlap(output, output_length,
	    view->registry_wire, view->registry_length) ||
	    vmx_nested_state_ranges_overlap(output, output_length,
	    view->l2_wire, view->l2_length));
}

int
vmx_nested_checkpoint_context_restore(struct vmx_nested_context *context,
    struct vmx_nested_control_msr_state *control,
    struct vmx_nested_vmcs_registry *registry, uint32_t owner,
    const struct vmx_nested_checkpoint_view *view, bool frozen)
{
	struct vmx_nested_context candidate;
	struct vmx_nested_control_msr_state candidate_control;
	const uint32_t unsupported = VMX_NESTED_STATE_F_GUEST_MODE |
	    VMX_NESTED_STATE_F_RUN_PENDING | VMX_NESTED_STATE_F_MTF_PENDING |
	    VMX_NESTED_STATE_F_SHADOW_VALID |
	    VMX_NESTED_STATE_F_PREEMPT_DEADLINE;
	uint64_t generation;
	bool owner_active;
	int error;

	if (context == NULL || control == NULL || registry == NULL ||
	    view == NULL || !frozen ||
	    owner == VMX_NESTED_VMCS_NO_OWNER)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(context, sizeof(*context), control,
	    sizeof(*control)) ||
	    nvmxcp_registry_overlap(registry, context, sizeof(*context)) ||
	    nvmxcp_registry_overlap(registry, control, sizeof(*control)) ||
	    nvmxcp_registry_overlap(registry, view, sizeof(*view)) ||
	    nvmxcp_registry_overlap(registry, view->state.vmcs_wire,
	    (size_t)view->state.vmcs_field_count *
	    VMX_NESTED_STATE_FIELD_SIZE) ||
	    nvmxcp_registry_overlap(registry, view->state.shadow_wire,
	    (size_t)view->state.shadow_field_count *
	    VMX_NESTED_STATE_FIELD_SIZE) ||
	    nvmxcp_registry_overlap(registry, view->registry_wire,
	    view->registry_length) ||
	    nvmxcp_registry_overlap(registry, view->l2_wire,
	    view->l2_length) ||
	    nvmxcp_view_output_overlap(view, context, sizeof(*context)) ||
	    nvmxcp_view_output_overlap(view, control, sizeof(*control)))
		return (EINVAL);
	error = vmx_nested_context_quiesce(context);
	if (error != 0)
		return (error);
	if (context->phase != VMX_NESTED_CONTEXT_ROOT ||
	    context->machine.vmxon ||
	    control->feature_control != 0)
		return (EBUSY);
	error = vmx_nested_state_destination_validate(&view->state,
	    &registry->capabilities);
	if (error != 0)
		return (error);
	if ((view->state.flags & unsupported) != 0)
		return (ENOTSUP);
	error = nvmxcp_owner_present(registry, owner, &owner_active);
	if (error != 0)
		return (error);
	if (owner_active)
		return (EBUSY);
	error = nvmxcp_restored_current_validate(registry, &view->state);
	if (error != 0)
		return (error);
	candidate_control.feature_control = view->state.feature_control;
	error = vmx_nested_control_msr_validate(&candidate_control);
	if (error != 0)
		return (error);
	if (context->state_generation == UINT64_MAX)
		return (EOVERFLOW);
	generation = context->state_generation + 1;
	vmx_nested_context_init(&candidate);
	candidate.state_generation = generation;
	if ((view->state.flags & VMX_NESTED_STATE_F_VMXON) != 0) {
		candidate.machine.vmxon = true;
		candidate.machine.vmxon_gpa = view->state.vmxon_gpa;
		candidate.machine.current_vmcs_gpa =
		    view->state.current_vmcs_gpa;
		candidate.machine.epoch = view->state.vmx_epoch;
		candidate.abort_indicator = view->state.abort_indicator;
		candidate.phase = candidate.abort_indicator != 0 ?
		    VMX_NESTED_CONTEXT_ABORTED : VMX_NESTED_CONTEXT_ROOT;
	}
	if (view->state.current_vmcs_gpa !=
	    VMX_NESTED_STATE_INVALID_GPA) {
		error = vmx_nested_vmcs_registry_select(registry,
		    view->state.current_vmcs_gpa,
		    registry->capabilities.revision_id, owner);
		if (error != 0)
			return (error);
	}
	*context = candidate;
	*control = candidate_control;
	return (0);
}

int
vmx_nested_checkpoint_active_context_restore(
    struct vmx_nested_context *context,
    struct vmx_nested_control_msr_state *control,
    struct vmx_nested_l0_continuation *continuation,
    struct vmx_nested_entry_runtime *runtime,
    struct vmx_nested_l2_portable_state *portable,
    struct vmx_nested_vmcs12_snapshot *snapshot,
    struct vmx_nested_vmcs_registry *registry, uint32_t owner,
    const struct vmx_nested_checkpoint_view *view, bool frozen)
{
	const uint32_t required = VMX_NESTED_STATE_F_VMXON |
	    VMX_NESTED_STATE_F_GUEST_MODE |
	    VMX_NESTED_STATE_F_CURRENT_LAUNCHED;
	const uint32_t allowed = required | VMX_NESTED_STATE_F_MTF_PENDING |
	    VMX_NESTED_STATE_F_SHADOW_VALID;
	struct vmx_nested_context candidate_context;
	struct vmx_nested_control_msr_state candidate_control;
	struct vmx_nested_l0_continuation candidate_continuation;
	struct vmx_nested_continuation_handoff_request continuation_request;
	struct vmx_nested_entry_runtime candidate_runtime;
	struct vmx_nested_l2_portable_state candidate_portable;
	struct vmx_nested_vmcs12_snapshot candidate_snapshot;
	struct vmx_nested_vmcs_registry_entry *entry;
	uint64_t launched_epoch;
	bool launched, owner_active;
	int error;

	if (context == NULL || control == NULL || continuation == NULL ||
	    runtime == NULL || portable == NULL || snapshot == NULL ||
	    registry == NULL ||
	    view == NULL || !frozen || owner == VMX_NESTED_VMCS_NO_OWNER ||
	    view->l2_wire == NULL ||
	    view->l2_length != VMX_NESTED_L2_CONT_STATE_SIZE ||
	    nvmxcp_view_output_overlap(view, context, sizeof(*context)) ||
	    nvmxcp_view_output_overlap(view, control, sizeof(*control)) ||
	    nvmxcp_view_output_overlap(view, continuation,
	    sizeof(*continuation)) ||
	    nvmxcp_view_output_overlap(view, runtime, sizeof(*runtime)) ||
	    nvmxcp_view_output_overlap(view, portable, sizeof(*portable)) ||
	    nvmxcp_view_output_overlap(view, snapshot, sizeof(*snapshot)) ||
	    nvmxcp_registry_overlap(registry, view, sizeof(*view)) ||
	    nvmxcp_registry_overlap(registry, view->state.vmcs_wire,
	    (size_t)view->state.vmcs_field_count *
	    VMX_NESTED_STATE_FIELD_SIZE) ||
	    nvmxcp_registry_overlap(registry, view->state.shadow_wire,
	    (size_t)view->state.shadow_field_count *
	    VMX_NESTED_STATE_FIELD_SIZE) ||
	    nvmxcp_registry_overlap(registry, view->registry_wire,
	    view->registry_length) ||
	    nvmxcp_registry_overlap(registry, view->l2_wire,
	    view->l2_length) ||
	    nvmxcp_registry_overlap(registry, context, sizeof(*context)) ||
	    nvmxcp_registry_overlap(registry, control, sizeof(*control)) ||
	    nvmxcp_registry_overlap(registry, continuation,
	    sizeof(*continuation)) ||
	    nvmxcp_registry_overlap(registry, runtime, sizeof(*runtime)) ||
	    nvmxcp_registry_overlap(registry, portable, sizeof(*portable)) ||
	    nvmxcp_registry_overlap(registry, snapshot, sizeof(*snapshot)) ||
	    vmx_nested_state_ranges_overlap(context, sizeof(*context), control,
	    sizeof(*control)) ||
	    vmx_nested_state_ranges_overlap(context, sizeof(*context), continuation,
	    sizeof(*continuation)) ||
	    vmx_nested_state_ranges_overlap(context, sizeof(*context), runtime,
	    sizeof(*runtime)) ||
	    vmx_nested_state_ranges_overlap(context, sizeof(*context), portable,
	    sizeof(*portable)) ||
	    vmx_nested_state_ranges_overlap(control, sizeof(*control), continuation,
	    sizeof(*continuation)) ||
	    vmx_nested_state_ranges_overlap(control, sizeof(*control), runtime,
	    sizeof(*runtime)) ||
	    vmx_nested_state_ranges_overlap(control, sizeof(*control), portable,
	    sizeof(*portable)) ||
	    vmx_nested_state_ranges_overlap(continuation, sizeof(*continuation),
	    runtime, sizeof(*runtime)) ||
	    vmx_nested_state_ranges_overlap(continuation, sizeof(*continuation),
	    portable, sizeof(*portable)) ||
	    vmx_nested_state_ranges_overlap(runtime, sizeof(*runtime), portable,
	    sizeof(*portable)) ||
	    vmx_nested_state_ranges_overlap(continuation, sizeof(*continuation),
	    snapshot, sizeof(*snapshot)) ||
	    vmx_nested_state_ranges_overlap(snapshot, sizeof(*snapshot), context,
	    sizeof(*context)) ||
	    vmx_nested_state_ranges_overlap(snapshot, sizeof(*snapshot), control,
	    sizeof(*control)) ||
	    vmx_nested_state_ranges_overlap(snapshot, sizeof(*snapshot), runtime,
	    sizeof(*runtime)) ||
	    vmx_nested_state_ranges_overlap(snapshot, sizeof(*snapshot), portable,
	    sizeof(*portable)))
		return (EINVAL);
	if (!registry->initialized ||
	    vmx_nested_context_quiesce(context) != 0 ||
	    context->phase != VMX_NESTED_CONTEXT_ROOT ||
	    context->machine.vmxon || control->feature_control != 0 ||
	    continuation->state != VMX_NESTED_L0_CONTINUATION_IDLE ||
	    vmx_nested_l0_continuation_validate(continuation) != 0 ||
	    runtime->state != VMX_NESTED_ENTRY_RUNTIME_IDLE ||
	    vmx_nested_entry_runtime_validate(runtime) != 0)
		return (EBUSY);
	error = vmx_nested_state_destination_validate(&view->state,
	    &registry->capabilities);
	if (error != 0)
		return (error);
	/*
	 * RUN_PENDING and the old absolute timer-deadline field require
	 * additional reconstruction semantics.  Pending MTF is owned by the
	 * generation-bound portable L2 image and is cross-checked below.
	 */
	if ((view->state.flags & required) != required ||
	    (view->state.flags & ~allowed) != 0 ||
	    view->state.abort_indicator != 0 ||
	    view->state.current_vmcs_gpa ==
	    VMX_NESTED_STATE_INVALID_GPA)
		return (ENOTSUP);
	error = nvmxcp_owner_present(registry, owner, &owner_active);
	if (error != 0)
		return (error);
	if (owner_active)
		return (EBUSY);
	error = nvmxcp_restored_current_validate(registry, &view->state);
	if (error != 0)
		return (error);
	candidate_control.feature_control = view->state.feature_control;
	error = vmx_nested_control_msr_validate(&candidate_control);
	if (error != 0)
		return (error);

	candidate_continuation = *continuation;
	candidate_runtime = *runtime;
	memset(&candidate_portable, 0, sizeof(candidate_portable));
	error = vmx_nested_l2_continuation_state_restore_cold(
	    &candidate_continuation, &candidate_runtime,
	    &candidate_portable, &registry->capabilities, view->l2_wire,
	    view->l2_length, true);
	if (error != 0)
		return (error);
	if (candidate_portable.id.vmcs12_gpa !=
	    view->state.current_vmcs_gpa)
		return (ESTALE);
	if (candidate_portable.mtf_pending !=
	    ((view->state.flags & VMX_NESTED_STATE_F_MTF_PENDING) != 0))
		return (ESTALE);
	error = nvmxcp_entry(registry, view->state.current_vmcs_gpa, &entry);
	if (error != 0)
		return (error);
	if (entry == NULL)
		return (ESTALE);
	error = vmx_nested_vmcs_region_launched(entry->region,
	    sizeof(entry->region), &registry->capabilities, false,
	    &launched, &launched_epoch);
	if (error != 0)
		return (error);
	if (!launched ||
	    launched_epoch != candidate_portable.id.execution_epoch)
		return (ESTALE);
	error = vmx_nested_vmcs12_snapshot_region(entry->region,
	    sizeof(entry->region), &registry->capabilities,
	    view->state.current_vmcs_gpa, false, &candidate_snapshot);
	if (error != 0)
		return (error);
	if (!candidate_snapshot.launched ||
	    candidate_snapshot.launch_epoch !=
	    candidate_portable.id.execution_epoch ||
	    candidate_snapshot.vmcs12_gpa !=
	    candidate_portable.id.vmcs12_gpa ||
	    candidate_snapshot.capability_signature !=
	    candidate_portable.capability_signature ||
	    (candidate_portable.mtf_pending &&
	    (candidate_snapshot.controls.primary & NVMXCP_PRIMARY_MTF) == 0) ||
	    (vmx_nested_link_state_required(
	        candidate_snapshot.controls.primary,
	        candidate_snapshot.controls.secondary,
	        candidate_snapshot.controls.vmentry,
	        candidate_snapshot.controls.in_smm,
	        candidate_snapshot.guest_arch.in_smm,
	        candidate_snapshot.link_pointer) !=
	    ((view->state.flags &
	    VMX_NESTED_STATE_F_SHADOW_VALID) != 0)))
		return (ESTALE);

	vmx_nested_context_init(&candidate_context);
	candidate_context.state_generation =
	    candidate_portable.id.state_generation;
	candidate_context.execution_epoch =
	    candidate_portable.id.execution_epoch;
	candidate_context.machine.vmxon = true;
	candidate_context.machine.vmxon_gpa = view->state.vmxon_gpa;
	candidate_context.machine.current_vmcs_gpa =
	    view->state.current_vmcs_gpa;
	candidate_context.machine.epoch = view->state.vmx_epoch;
	candidate_context.phase = VMX_NESTED_CONTEXT_GUEST;
	error = vmx_nested_continuation_handoff_request_build(
	    &candidate_continuation, &continuation_request);
	if (error != 0)
		return (error);
	error = vmx_nested_internal_publish_continuation(
	    &candidate_context.internal, &continuation_request);
	if (error != 0)
		return (error);
	error = vmx_nested_l0_continuation_quiesce_context(
	    &candidate_context, &candidate_continuation,
	    &candidate_runtime, &candidate_portable);
	if (error != 0)
		return (error);

	/*
	 * Selecting the VMCS is the final fallible operation.  No subsequent
	 * operation can leave the registry owned while outputs remain old.
	 */
	error = vmx_nested_vmcs_registry_select(registry,
	    view->state.current_vmcs_gpa,
	    registry->capabilities.revision_id, owner);
	if (error != 0)
		return (error);
	*context = candidate_context;
	*control = candidate_control;
	*continuation = candidate_continuation;
	*runtime = candidate_runtime;
	*portable = candidate_portable;
	*snapshot = candidate_snapshot;
	return (0);
}
