/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/endian.h>
#include <sys/errno.h>
#include <sys/types.h>

#ifdef _KERNEL
#include <sys/systm.h>
#else
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#endif

#include "vmx_nested_state.h"
#include "vmx_nested_caps.h"
#include "vmx_nested_control_msr.h"
#include "vmx_nested_state_range.h"
#include "vmx_nested_vmcs.h"

#define	VMX_NESTED_STATE_MAGIC		0x31584d4eU	/* "NMX1" */
#define	VMX_NESTED_STATE_VERSION	2U
#define	VMX_NESTED_STATE_DIGEST_OFFSET	88U
#define	VMX_NESTED_REGION_MASK		(UINT64_C(4096) - 1)
#define	VMX_NESTED_STATE_ALL_FLAGS				\
	(VMX_NESTED_STATE_F_VMXON | VMX_NESTED_STATE_F_GUEST_MODE |	\
	 VMX_NESTED_STATE_F_RUN_PENDING | VMX_NESTED_STATE_F_MTF_PENDING | \
	 VMX_NESTED_STATE_F_SHADOW_VALID |				\
	 VMX_NESTED_STATE_F_PREEMPT_DEADLINE |			\
	 VMX_NESTED_STATE_F_CURRENT_LAUNCHED)

static uint64_t
vmx_nested_state_digest(const uint8_t *bytes, size_t length)
{
	uint64_t digest;

	digest = UINT64_C(14695981039346656037);
	for (size_t i = 0; i < length; i++) {
		uint8_t byte;

		byte = i >= VMX_NESTED_STATE_DIGEST_OFFSET &&
		    i < VMX_NESTED_STATE_DIGEST_OFFSET + sizeof(uint64_t) ?
		    0 : bytes[i];
		digest ^= byte;
		digest *= UINT64_C(1099511628211);
	}
	return (digest);
}

static int
vmx_nested_fields_validate(const struct vmx_nested_field *fields,
    uint32_t count)
{
	struct vmx_nested_vmcs_field_info info;
	uint32_t previous;

	if (count > VMX_NESTED_STATE_MAX_FIELDS ||
	    (count != 0 && fields == NULL))
		return (EINVAL);
	previous = 0;
	for (uint32_t i = 0; i < count; i++) {
		/*
		 * Bits above 14 are reserved in Intel's VMCS field encoding.
		 * Access-type 1 names the high half of a 64-bit field; the
		 * canonical state stores each full field once.
		 */
		if ((fields[i].encoding & UINT32_C(0xffff8001)) != 0 ||
		    vmx_nested_vmcs_field_info(fields[i].encoding, &info) != 0 ||
		    info.high_half || fields[i].width != info.width ||
		    (i != 0 && fields[i].encoding <= previous) ||
		    (fields[i].width == 2 && fields[i].value > UINT16_MAX) ||
		    (fields[i].width == 4 && fields[i].value > UINT32_MAX))
			return (EINVAL);
		previous = fields[i].encoding;
	}
	return (0);
}

static int
vmx_nested_state_dependencies(const struct vmx_nested_state *state)
{
	struct vmx_nested_control_msr_state control_msr;
	const uint32_t current_flags = VMX_NESTED_STATE_F_GUEST_MODE |
	    VMX_NESTED_STATE_F_RUN_PENDING | VMX_NESTED_STATE_F_MTF_PENDING |
	    VMX_NESTED_STATE_F_SHADOW_VALID |
	    VMX_NESTED_STATE_F_PREEMPT_DEADLINE |
	    VMX_NESTED_STATE_F_CURRENT_LAUNCHED;
	bool current;

	if ((state->flags & ~VMX_NESTED_STATE_ALL_FLAGS) != 0)
		return (EINVAL);
	control_msr.feature_control = state->feature_control;
	if (vmx_nested_control_msr_validate(&control_msr) != 0)
		return (EINVAL);
	current = state->current_vmcs_gpa != VMX_NESTED_STATE_INVALID_GPA;
	if ((state->flags & VMX_NESTED_STATE_F_VMXON) == 0) {
		if (state->flags != 0 ||
		    state->vmxon_gpa != VMX_NESTED_STATE_INVALID_GPA ||
		    current || state->preemption_timer_deadline_ticks != 0 ||
		    state->capability_signature != 0 ||
		    state->schema_signature != 0 ||
		    state->vmx_epoch != 0 ||
		    state->revision_id != 0 || state->abort_indicator != 0 ||
		    state->vmcs_field_count != 0 ||
		    state->shadow_field_count != 0)
			return (EINVAL);
		return (0);
	}
	if (state->vmxon_gpa == VMX_NESTED_STATE_INVALID_GPA ||
	    (state->vmxon_gpa & VMX_NESTED_REGION_MASK) != 0 ||
	    state->capability_signature == 0 || state->schema_signature == 0 ||
	    state->vmx_epoch == 0 ||
	    (state->feature_control &
	    (VMX_NESTED_FEATURE_CONTROL_LOCK |
	    VMX_NESTED_FEATURE_CONTROL_VMX_OUTSIDE_SMX)) !=
	    (VMX_NESTED_FEATURE_CONTROL_LOCK |
	    VMX_NESTED_FEATURE_CONTROL_VMX_OUTSIDE_SMX))
		return (EINVAL);
	if (!current) {
		if ((state->flags & current_flags) != 0 ||
		    state->preemption_timer_deadline_ticks != 0 ||
		    state->revision_id != 0 || state->abort_indicator != 0 ||
		    state->vmcs_field_count != 0 ||
		    state->shadow_field_count != 0)
			return (EINVAL);
		return (0);
	}
	if ((state->current_vmcs_gpa & VMX_NESTED_REGION_MASK) != 0 ||
	    state->current_vmcs_gpa == state->vmxon_gpa ||
	    state->revision_id > INT32_MAX || state->abort_indicator > 6)
		return (EINVAL);
	if (state->abort_indicator != 0 &&
	    (state->flags & (VMX_NESTED_STATE_F_GUEST_MODE |
	    VMX_NESTED_STATE_F_RUN_PENDING | VMX_NESTED_STATE_F_MTF_PENDING |
	    VMX_NESTED_STATE_F_SHADOW_VALID |
	    VMX_NESTED_STATE_F_PREEMPT_DEADLINE)) != 0)
		return (EINVAL);
	if ((state->flags & VMX_NESTED_STATE_F_GUEST_MODE) != 0 &&
	    (state->flags & VMX_NESTED_STATE_F_CURRENT_LAUNCHED) == 0)
		return (EINVAL);
	if ((state->flags & VMX_NESTED_STATE_F_RUN_PENDING) != 0 &&
	    (state->flags & VMX_NESTED_STATE_F_GUEST_MODE) == 0)
		return (EINVAL);
	if ((state->flags & VMX_NESTED_STATE_F_MTF_PENDING) != 0 &&
	    (state->flags & VMX_NESTED_STATE_F_GUEST_MODE) == 0)
		return (EINVAL);
	if ((state->flags & VMX_NESTED_STATE_F_SHADOW_VALID) != 0 &&
	    (state->flags & VMX_NESTED_STATE_F_GUEST_MODE) == 0)
		return (EINVAL);
	if ((state->flags & VMX_NESTED_STATE_F_PREEMPT_DEADLINE) != 0 &&
	    (state->flags & VMX_NESTED_STATE_F_GUEST_MODE) == 0)
		return (EINVAL);
	if ((state->flags & VMX_NESTED_STATE_F_PREEMPT_DEADLINE) == 0 &&
	    state->preemption_timer_deadline_ticks != 0)
		return (EINVAL);
	if ((state->flags & VMX_NESTED_STATE_F_SHADOW_VALID) == 0 &&
	    state->shadow_field_count != 0)
		return (EINVAL);
	return (0);
}

static int
vmx_nested_state_semantics(const struct vmx_nested_state *state)
{
	int error;

	error = vmx_nested_state_dependencies(state);
	if (error != 0)
		return (error);
	error = vmx_nested_fields_validate(state->vmcs_fields,
	    state->vmcs_field_count);
	if (error != 0)
		return (error);
	return (vmx_nested_fields_validate(state->shadow_fields,
	    state->shadow_field_count));
}

static void
vmx_nested_field_encode(uint8_t *bytes, const struct vmx_nested_field *field)
{

	memset(bytes, 0, VMX_NESTED_STATE_FIELD_SIZE);
	le32enc(bytes, field->encoding);
	bytes[4] = field->width;
	le64enc(bytes + 8, field->value);
}

int
vmx_nested_state_size(const struct vmx_nested_state *state, size_t *size)
{
	size_t total, vmcs_length, shadow_length;
	int error;

	if (state == NULL || size == NULL)
		return (EINVAL);
	/*
	 * Validate the architectural counts before using them in host-sized
	 * pointer-range arithmetic.  This ordering matters on a 32-bit host,
	 * where an untrusted uint32_t count could otherwise wrap size_t.
	 */
	error = vmx_nested_state_semantics(state);
	if (error != 0)
		return (error);
	if (vmx_nested_state_ranges_overlap(size, sizeof(*size), state,
	    sizeof(*state)) ||
	    vmx_nested_state_ranges_overlap(size, sizeof(*size),
	    state->vmcs_fields, (size_t)state->vmcs_field_count *
	    sizeof(*state->vmcs_fields)) ||
	    vmx_nested_state_ranges_overlap(size, sizeof(*size),
	    state->shadow_fields, (size_t)state->shadow_field_count *
	    sizeof(*state->shadow_fields)))
		return (EINVAL);
	vmcs_length = (size_t)state->vmcs_field_count *
	    VMX_NESTED_STATE_FIELD_SIZE;
	shadow_length = (size_t)state->shadow_field_count *
	    VMX_NESTED_STATE_FIELD_SIZE;
	if (vmcs_length > SIZE_MAX - VMX_NESTED_STATE_HEADER_SIZE ||
	    shadow_length > SIZE_MAX -
	    (VMX_NESTED_STATE_HEADER_SIZE + vmcs_length))
		return (EOVERFLOW);
	total = VMX_NESTED_STATE_HEADER_SIZE + vmcs_length + shadow_length;
	if (total > UINT32_MAX)
		return (EOVERFLOW);
	*size = total;
	return (0);
}

int
vmx_nested_state_encode(const struct vmx_nested_state *state, void *buffer,
    size_t capacity, size_t *written)
{
	uint8_t *bytes;
	size_t total, vmcs_length;
	int error;

	if (state == NULL || buffer == NULL || written == NULL)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(state, sizeof(*state), written,
	    sizeof(*written)))
		return (EINVAL);
	error = vmx_nested_state_size(state, &total);
	if (error != 0)
		return (error);
	vmcs_length = (size_t)state->vmcs_field_count *
	    VMX_NESTED_STATE_FIELD_SIZE;
	if (vmx_nested_state_ranges_overlap(buffer, total, state, sizeof(*state)) ||
	    vmx_nested_state_ranges_overlap(buffer, total, state->vmcs_fields,
	    (size_t)state->vmcs_field_count * sizeof(*state->vmcs_fields)) ||
	    vmx_nested_state_ranges_overlap(buffer, total, state->shadow_fields,
	    (size_t)state->shadow_field_count *
	    sizeof(*state->shadow_fields)) ||
	    vmx_nested_state_ranges_overlap(buffer, total, written,
	    sizeof(*written)) ||
	    vmx_nested_state_ranges_overlap(written, sizeof(*written),
	    state->vmcs_fields, (size_t)state->vmcs_field_count *
	    sizeof(*state->vmcs_fields)) ||
	    vmx_nested_state_ranges_overlap(written, sizeof(*written),
	    state->shadow_fields, (size_t)state->shadow_field_count *
	    sizeof(*state->shadow_fields)))
		return (EINVAL);
	*written = 0;
	if (capacity < total)
		return (ENOSPC);

	bytes = buffer;
	memset(bytes, 0, total);
	le32enc(bytes, VMX_NESTED_STATE_MAGIC);
	le16enc(bytes + 4, VMX_NESTED_STATE_VERSION);
	le16enc(bytes + 6, VMX_NESTED_STATE_HEADER_SIZE);
	le32enc(bytes + 8, (uint32_t)total);
	le32enc(bytes + 12, state->flags);
	le64enc(bytes + 16, state->vmxon_gpa);
	le64enc(bytes + 24, state->current_vmcs_gpa);
	le64enc(bytes + 32, state->preemption_timer_deadline_ticks);
	le64enc(bytes + 40, state->capability_signature);
	le64enc(bytes + 48, state->schema_signature);
	le64enc(bytes + 56, state->vmx_epoch);
	le32enc(bytes + 64, state->vmcs_field_count);
	le32enc(bytes + 68, state->shadow_field_count);
	le32enc(bytes + 72, state->revision_id);
	le32enc(bytes + 76, state->abort_indicator);
	le64enc(bytes + 80, state->feature_control);
	for (uint32_t i = 0; i < state->vmcs_field_count; i++)
		vmx_nested_field_encode(bytes + VMX_NESTED_STATE_HEADER_SIZE +
		    (size_t)i * VMX_NESTED_STATE_FIELD_SIZE,
		    &state->vmcs_fields[i]);
	for (uint32_t i = 0; i < state->shadow_field_count; i++)
		vmx_nested_field_encode(bytes + VMX_NESTED_STATE_HEADER_SIZE +
		    vmcs_length + (size_t)i * VMX_NESTED_STATE_FIELD_SIZE,
		    &state->shadow_fields[i]);
	le64enc(bytes + VMX_NESTED_STATE_DIGEST_OFFSET,
	    vmx_nested_state_digest(bytes, total));
	*written = total;
	return (0);
}

static int
vmx_nested_wire_fields(const uint8_t *bytes, uint32_t count)
{
	struct vmx_nested_vmcs_field_info info;
	uint32_t encoding, previous;
	uint64_t value;
	uint8_t width;

	previous = 0;
	for (uint32_t i = 0; i < count; i++) {
		encoding = le32dec(bytes);
		width = bytes[4];
		value = le64dec(bytes + 8);
		if (bytes[5] != 0 || le16dec(bytes + 6) != 0 ||
		    (encoding & UINT32_C(0xffff8001)) != 0 ||
		    vmx_nested_vmcs_field_info(encoding, &info) != 0 ||
		    info.high_half || width != info.width ||
		    (i != 0 && encoding <= previous) ||
		    (width == 2 && value > UINT16_MAX) ||
		    (width == 4 && value > UINT32_MAX))
			return (EPROTO);
		previous = encoding;
		bytes += VMX_NESTED_STATE_FIELD_SIZE;
	}
	return (0);
}

int
vmx_nested_state_decode(const void *buffer, size_t length,
    struct vmx_nested_state_view *view)
{
	struct vmx_nested_state semantic;
	const uint8_t *bytes, *vmcs_wire, *shadow_wire;
	uint32_t shadow_count, vmcs_count;
	size_t expected;
	int error;

	if (buffer == NULL || view == NULL)
		return (EINVAL);
	if (length < VMX_NESTED_STATE_HEADER_SIZE)
		return (EMSGSIZE);
	if (length > VMX_NESTED_STATE_MAX_SIZE)
		return (E2BIG);
	/*
	 * A successful view retains pointers into the wire image.  Publishing
	 * that view over any part of its own backing buffer would corrupt the
	 * decoded fields and violate the immutable-view contract.
	 */
	if (vmx_nested_state_ranges_overlap(buffer, length, view, sizeof(*view)))
		return (EINVAL);
	bytes = buffer;
	if (le32dec(bytes) != VMX_NESTED_STATE_MAGIC ||
	    le16dec(bytes + 4) != VMX_NESTED_STATE_VERSION ||
	    le16dec(bytes + 6) != VMX_NESTED_STATE_HEADER_SIZE ||
	    le32dec(bytes + 8) != length ||
	    le64dec(bytes + VMX_NESTED_STATE_DIGEST_OFFSET) !=
	    vmx_nested_state_digest(bytes, length))
		return (EPROTO);
	vmcs_count = le32dec(bytes + 64);
	shadow_count = le32dec(bytes + 68);
	if (vmcs_count > VMX_NESTED_STATE_MAX_FIELDS ||
	    shadow_count > VMX_NESTED_STATE_MAX_FIELDS)
		return (EPROTO);
	expected = VMX_NESTED_STATE_HEADER_SIZE +
	    (size_t)vmcs_count * VMX_NESTED_STATE_FIELD_SIZE +
	    (size_t)shadow_count * VMX_NESTED_STATE_FIELD_SIZE;
	if (expected != length)
		return (EPROTO);
	vmcs_wire = bytes + VMX_NESTED_STATE_HEADER_SIZE;
	shadow_wire = vmcs_wire +
	    (size_t)vmcs_count * VMX_NESTED_STATE_FIELD_SIZE;
	error = vmx_nested_wire_fields(vmcs_wire, vmcs_count);
	if (error != 0)
		return (error);
	error = vmx_nested_wire_fields(shadow_wire, shadow_count);
	if (error != 0)
		return (error);

	memset(&semantic, 0, sizeof(semantic));
	semantic.flags = le32dec(bytes + 12);
	semantic.vmxon_gpa = le64dec(bytes + 16);
	semantic.current_vmcs_gpa = le64dec(bytes + 24);
	semantic.preemption_timer_deadline_ticks = le64dec(bytes + 32);
	semantic.capability_signature = le64dec(bytes + 40);
	semantic.schema_signature = le64dec(bytes + 48);
	semantic.vmx_epoch = le64dec(bytes + 56);
	semantic.feature_control = le64dec(bytes + 80);
	semantic.vmcs_field_count = vmcs_count;
	semantic.shadow_field_count = shadow_count;
	semantic.revision_id = le32dec(bytes + 72);
	semantic.abort_indicator = le32dec(bytes + 76);
	error = vmx_nested_state_dependencies(&semantic);
	if (error != 0)
		return (EPROTO);

	view->flags = semantic.flags;
	view->vmxon_gpa = semantic.vmxon_gpa;
	view->current_vmcs_gpa = semantic.current_vmcs_gpa;
	view->preemption_timer_deadline_ticks =
	    semantic.preemption_timer_deadline_ticks;
	view->capability_signature = semantic.capability_signature;
	view->schema_signature = semantic.schema_signature;
	view->vmx_epoch = semantic.vmx_epoch;
	view->feature_control = semantic.feature_control;
	view->revision_id = semantic.revision_id;
	view->abort_indicator = semantic.abort_indicator;
	view->vmcs_field_count = vmcs_count;
	view->shadow_field_count = shadow_count;
	view->vmcs_wire = vmcs_wire;
	view->shadow_wire = shadow_wire;
	return (0);
}

int
vmx_nested_state_view_field(const struct vmx_nested_state_view *view,
    bool shadow, uint32_t index, struct vmx_nested_field *field)
{
	struct vmx_nested_field candidate;
	const uint8_t *bytes;
	size_t shadow_length, vmcs_length;
	uint32_t count;

	if (view == NULL || field == NULL)
		return (EINVAL);
	count = shadow ? view->shadow_field_count : view->vmcs_field_count;
	bytes = shadow ? view->shadow_wire : view->vmcs_wire;
	if (view->vmcs_field_count > VMX_NESTED_STATE_MAX_FIELDS ||
	    view->shadow_field_count > VMX_NESTED_STATE_MAX_FIELDS)
		return (EINVAL);
	vmcs_length = (size_t)view->vmcs_field_count *
	    VMX_NESTED_STATE_FIELD_SIZE;
	shadow_length = (size_t)view->shadow_field_count *
	    VMX_NESTED_STATE_FIELD_SIZE;
	if ((vmcs_length != 0 && view->vmcs_wire == NULL) ||
	    (shadow_length != 0 && view->shadow_wire == NULL) ||
	    vmx_nested_state_ranges_overlap(view, sizeof(*view), field,
	    sizeof(*field)) ||
	    vmx_nested_state_ranges_overlap(view->vmcs_wire, vmcs_length,
	    field, sizeof(*field)) ||
	    vmx_nested_state_ranges_overlap(view->shadow_wire, shadow_length,
	    field, sizeof(*field)) ||
	    vmx_nested_state_ranges_overlap(view->vmcs_wire, vmcs_length,
	    view->shadow_wire, shadow_length))
		return (EINVAL);
	if (index >= count)
		return (ENOENT);
	bytes += (size_t)index * VMX_NESTED_STATE_FIELD_SIZE;
	candidate.encoding = le32dec(bytes);
	candidate.width = bytes[4];
	candidate.value = le64dec(bytes + 8);
	*field = candidate;
	return (0);
}

int
vmx_nested_state_compatible(const struct vmx_nested_state_view *view,
    uint64_t capability_signature, uint64_t schema_signature,
    uint32_t revision_id)
{
	bool current;

	if (view == NULL || capability_signature == 0 || schema_signature == 0 ||
	    revision_id > INT32_MAX)
		return (EINVAL);
	if ((view->flags & VMX_NESTED_STATE_F_VMXON) == 0)
		return (0);
	if (view->capability_signature != capability_signature ||
	    view->schema_signature != schema_signature)
		return (ENOTSUP);
	current = view->current_vmcs_gpa != VMX_NESTED_STATE_INVALID_GPA;
	if (current && view->revision_id != revision_id)
		return (ENOTSUP);
	return (0);
}

int
vmx_nested_state_destination_validate(
    const struct vmx_nested_state_view *view,
    const struct vmx_nested_capabilities *capabilities)
{
	uint64_t capability_signature;
	bool current;
	int error;

	if (view == NULL || capabilities == NULL)
		return (EINVAL);
	error = vmx_nested_capabilities_signature(capabilities,
	    &capability_signature);
	if (error != 0)
		return (error);
	error = vmx_nested_state_compatible(view, capability_signature,
	    vmx_nested_vmcs_schema_signature(), capabilities->revision_id);
	if (error != 0 ||
	    (view->flags & VMX_NESTED_STATE_F_VMXON) == 0)
		return (error);
	if (!vmx_nested_region_gpa_valid(capabilities, view->vmxon_gpa))
		return (ENOTSUP);
	current = view->current_vmcs_gpa != VMX_NESTED_STATE_INVALID_GPA;
	if (current &&
	    !vmx_nested_region_gpa_valid(capabilities, view->current_vmcs_gpa))
		return (ENOTSUP);
	return (0);
}
