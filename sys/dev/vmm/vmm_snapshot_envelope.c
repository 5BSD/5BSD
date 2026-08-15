/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 */

#include <sys/types.h>
#include <sys/endian.h>
#include <sys/errno.h>
#ifdef _KERNEL
#include <sys/systm.h>
#else
#include <string.h>
#endif

#include <dev/vmm/vmm_snapshot_envelope.h>
#include <dev/vmm/vmm_address_range.h>

bool
vmm_snapshot_range_valid(const void *base, size_t length)
{
	return (vmm_address_range_valid(base, length));
}

bool
vmm_snapshot_ranges_overlap(const void *left, size_t left_length,
    const void *right, size_t right_length)
{
	if (left_length == 0 || right_length == 0)
		return (false);
	/*
	 * This is a public range primitive, not merely an implementation detail
	 * of the envelope codec.  Do not give callers a plausible answer for an
	 * unrepresentable range: the subtraction below assumes both end points
	 * can describe complete, non-wrapping byte ranges.
	 */
	if (!vmm_snapshot_range_valid(left, left_length) ||
	    !vmm_snapshot_range_valid(right, right_length))
		return (false);
	return (vmm_address_ranges_overlap(left, left_length, right,
	    right_length));
}

/*
 * The builder is caller-owned state, but it is also a private kernel API used
 * across multi-step checkpoint construction.  Validate its complete retained
 * shape before every mutation: a damaged cursor or metadata marker must not
 * turn add() into a header overwrite or a non-canonical wire image and leave
 * finalize() or a later reader to discover it.
 */
static bool
vmm_snapshot_envelope_builder_sections_valid(
    const struct vmm_snapshot_envelope_builder *builder)
{
	const uint8_t *section;
	size_t cursor, payload_length;
	uint32_t instance, last_instance;
	uint16_t last_type, type;
	bool have_last;

	cursor = VMM_SNAPSHOT_ENVELOPE_HEADER_SIZE;
	have_last = false;
	last_type = 0;
	last_instance = 0;
	for (uint32_t i = 0; i < builder->section_count; i++) {
		if (VMM_SNAPSHOT_SECTION_HEADER_SIZE > builder->length - cursor)
			return (false);
		section = builder->buffer + cursor;
		type = le16dec(section);
		instance = le32dec(section + 8);
		if (type == 0 ||
		    (le16dec(section + 2) & ~VMM_SNAPSHOT_SECTION_F_VALID) != 0 ||
		    (have_last && (type < last_type ||
		    (type == last_type && instance <= last_instance))) ||
		    le32dec(section + 12) != 0 || le32dec(section + 16) != 0 ||
		    le32dec(section + 20) != 0)
			return (false);
		payload_length = le32dec(section + 4);
		cursor += VMM_SNAPSHOT_SECTION_HEADER_SIZE;
		if (payload_length > builder->length - cursor)
			return (false);
		cursor += payload_length;
		last_type = type;
		last_instance = instance;
		have_last = true;
	}
	return (cursor == builder->length &&
	    (have_last ? builder->has_last && builder->last_type == last_type &&
	    builder->last_instance == last_instance : !builder->has_last));
}

static bool
vmm_snapshot_envelope_builder_valid(
    const struct vmm_snapshot_envelope_builder *builder)
{

	if (builder == NULL ||
	    !vmm_snapshot_range_valid(builder, sizeof(*builder)) ||
	    builder->buffer == NULL ||
	    !vmm_snapshot_range_valid(builder->buffer, builder->capacity) ||
	    builder->capacity < VMM_SNAPSHOT_ENVELOPE_HEADER_SIZE ||
	    builder->length < VMM_SNAPSHOT_ENVELOPE_HEADER_SIZE ||
	    builder->length > builder->capacity ||
	    builder->section_count >
	    (builder->length - VMM_SNAPSHOT_ENVELOPE_HEADER_SIZE) /
	    VMM_SNAPSHOT_SECTION_HEADER_SIZE ||
	    (builder->section_count == 0 && builder->has_last) ||
	    (builder->section_count != 0 &&
	    (!builder->has_last || builder->last_type == 0)) ||
	    !vmm_snapshot_envelope_builder_sections_valid(builder))
		return (false);
	return (true);
}

int
vmm_snapshot_envelope_builder_init(
    struct vmm_snapshot_envelope_builder *builder, void *buffer,
    size_t capacity)
{
	struct vmm_snapshot_envelope_builder candidate;

	if (builder == NULL || buffer == NULL ||
	    capacity < VMM_SNAPSHOT_ENVELOPE_HEADER_SIZE ||
	    !vmm_snapshot_range_valid(builder, sizeof(*builder)) ||
	    !vmm_snapshot_range_valid(buffer, capacity) ||
	    vmm_snapshot_ranges_overlap(builder, sizeof(*builder), buffer,
	    capacity))
		return (EINVAL);
	candidate = (struct vmm_snapshot_envelope_builder) {
		.buffer = buffer,
		.capacity = capacity,
		.length = VMM_SNAPSHOT_ENVELOPE_HEADER_SIZE,
	};
	memset(buffer, 0, VMM_SNAPSHOT_ENVELOPE_HEADER_SIZE);
	*builder = candidate;
	return (0);
}

int
vmm_snapshot_envelope_add(struct vmm_snapshot_envelope_builder *builder,
    uint16_t type, uint16_t flags, uint32_t instance, const void *payload,
    size_t payload_length)
{
	uint8_t *section;
	size_t required;

	if (!vmm_snapshot_envelope_builder_valid(builder) || builder->finalized ||
	    !vmm_snapshot_range_valid(payload, payload_length) ||
	    type == 0 || (flags & ~VMM_SNAPSHOT_SECTION_F_VALID) != 0 ||
	    (builder->has_last && (type < builder->last_type ||
	    (type == builder->last_type &&
	    instance <= builder->last_instance))) ||
	    payload_length > UINT32_MAX ||
	    (payload == NULL && payload_length != 0) ||
	    builder->section_count == UINT32_MAX ||
	    builder->length > builder->capacity ||
	    VMM_SNAPSHOT_SECTION_HEADER_SIZE >
	    builder->capacity - builder->length ||
	    payload_length > builder->capacity - builder->length -
	    VMM_SNAPSHOT_SECTION_HEADER_SIZE)
		return (EINVAL);
	required = VMM_SNAPSHOT_SECTION_HEADER_SIZE + payload_length;
	if (vmm_snapshot_ranges_overlap(payload, payload_length,
	    builder->buffer + builder->length, required))
		return (EINVAL);

	section = builder->buffer + builder->length;
	memset(section, 0, VMM_SNAPSHOT_SECTION_HEADER_SIZE);
	le16enc(section, type);
	le16enc(section + 2, flags);
	le32enc(section + 4, (uint32_t)payload_length);
	le32enc(section + 8, instance);
	if (payload_length != 0)
		memmove(section + VMM_SNAPSHOT_SECTION_HEADER_SIZE, payload,
		    payload_length);
	builder->length += required;
	builder->section_count++;
	builder->last_type = type;
	builder->last_instance = instance;
	builder->has_last = true;
	return (0);
}

int
vmm_snapshot_envelope_finalize(struct vmm_snapshot_envelope_builder *builder,
    size_t *length)
{
	uint8_t *header;

	if (!vmm_snapshot_envelope_builder_valid(builder) || length == NULL ||
	    !vmm_snapshot_range_valid(length, sizeof(*length)) ||
	    vmm_snapshot_ranges_overlap(length, sizeof(*length), builder,
	    sizeof(*builder)) ||
	    builder->finalized || builder->length > UINT32_MAX ||
	    vmm_snapshot_ranges_overlap(length, sizeof(*length),
	    builder->buffer, builder->length))
		return (EINVAL);
	header = builder->buffer;
	le32enc(header, VMM_SNAPSHOT_ENVELOPE_MAGIC);
	le16enc(header + 4, VMM_SNAPSHOT_ENVELOPE_VERSION);
	le16enc(header + 6, VMM_SNAPSHOT_ENVELOPE_HEADER_SIZE);
	le32enc(header + 8, (uint32_t)builder->length);
	le32enc(header + 12, builder->section_count);
	le32enc(header + 16, VMM_SNAPSHOT_ENVELOPE_F_NONE);
	builder->finalized = true;
	*length = builder->length;
	return (0);
}

static int
vmm_snapshot_envelope_validate(const uint8_t *buffer, size_t length,
    uint32_t *section_count)
{
	size_t cursor, payload_length;
	uint32_t count;
	uint32_t instance, last_instance;
	uint16_t last_type, type;
	bool have_last;

	if (buffer == NULL || section_count == NULL ||
	    !vmm_snapshot_range_valid(buffer, length) ||
	    !vmm_snapshot_range_valid(section_count, sizeof(*section_count)) ||
	    length < VMM_SNAPSHOT_ENVELOPE_HEADER_SIZE || length > UINT32_MAX ||
	    le32dec(buffer) != VMM_SNAPSHOT_ENVELOPE_MAGIC ||
	    le16dec(buffer + 4) != VMM_SNAPSHOT_ENVELOPE_VERSION ||
	    le16dec(buffer + 6) != VMM_SNAPSHOT_ENVELOPE_HEADER_SIZE ||
	    le32dec(buffer + 8) != length ||
	    (le32dec(buffer + 16) & ~VMM_SNAPSHOT_ENVELOPE_F_VALID) != 0 ||
	    le32dec(buffer + 20) != 0 || le32dec(buffer + 24) != 0 ||
	    le32dec(buffer + 28) != 0)
		return (EINVAL);
	count = le32dec(buffer + 12);
	cursor = VMM_SNAPSHOT_ENVELOPE_HEADER_SIZE;
	have_last = false;
	last_type = 0;
	last_instance = 0;
	for (uint32_t i = 0; i < count; i++) {
		if (VMM_SNAPSHOT_SECTION_HEADER_SIZE > length - cursor)
			return (EINVAL);
		type = le16dec(buffer + cursor);
		instance = le32dec(buffer + cursor + 8);
		if (type == 0 ||
		    (le16dec(buffer + cursor + 2) &
		    ~VMM_SNAPSHOT_SECTION_F_VALID) != 0 ||
		    (have_last && (type < last_type ||
		    (type == last_type && instance <= last_instance))) ||
		    le32dec(buffer + cursor + 12) != 0 ||
		    le32dec(buffer + cursor + 16) != 0 ||
		    le32dec(buffer + cursor + 20) != 0)
			return (EINVAL);
		payload_length = le32dec(buffer + cursor + 4);
		cursor += VMM_SNAPSHOT_SECTION_HEADER_SIZE;
		if (payload_length > length - cursor)
			return (EINVAL);
		cursor += payload_length;
		last_type = type;
		last_instance = instance;
		have_last = true;
	}
	if (cursor != length)
		return (EINVAL);
	*section_count = count;
	return (0);
}

static int
vmm_snapshot_envelope_cursor(const uint8_t *buffer, size_t length,
    uint32_t sections_read, size_t *cursorp)
{
	size_t cursor, payload_length;

	if (buffer == NULL || cursorp == NULL ||
	    !vmm_snapshot_range_valid(buffer, length) ||
	    !vmm_snapshot_range_valid(cursorp, sizeof(*cursorp)))
		return (EINVAL);
	cursor = VMM_SNAPSHOT_ENVELOPE_HEADER_SIZE;
	for (uint32_t i = 0; i < sections_read; i++) {
		if (cursor > length || VMM_SNAPSHOT_SECTION_HEADER_SIZE >
		    length - cursor)
			return (EINVAL);
		payload_length = le32dec(buffer + cursor + 4);
		cursor += VMM_SNAPSHOT_SECTION_HEADER_SIZE;
		if (payload_length > length - cursor)
			return (EINVAL);
		cursor += payload_length;
	}
	*cursorp = cursor;
	return (0);
}

int
vmm_snapshot_envelope_reader_init(struct vmm_snapshot_envelope_reader *reader,
    const void *buffer, size_t length)
{
	struct vmm_snapshot_envelope_reader candidate;
	uint32_t section_count;
	int error;

	if (reader == NULL || !vmm_snapshot_range_valid(reader, sizeof(*reader)) ||
	    !vmm_snapshot_range_valid(buffer, length) ||
	    vmm_snapshot_ranges_overlap(reader,
	    sizeof(*reader), buffer, length))
		return (EINVAL);
	error = vmm_snapshot_envelope_validate(buffer, length, &section_count);
	if (error != 0)
		return (error);
	candidate = (struct vmm_snapshot_envelope_reader) {
		.buffer = buffer,
		.length = length,
		.cursor = VMM_SNAPSHOT_ENVELOPE_HEADER_SIZE,
		.section_count = section_count,
	};
	*reader = candidate;
	return (0);
}

int
vmm_snapshot_envelope_next(struct vmm_snapshot_envelope_reader *reader,
    struct vmm_snapshot_section *section)
{
	struct vmm_snapshot_section candidate;
	const uint8_t *wire;
	size_t expected_cursor, payload_length;
	uint32_t section_count;
	int error;

	if (reader == NULL || section == NULL ||
	    !vmm_snapshot_range_valid(reader, sizeof(*reader)) ||
	    !vmm_snapshot_range_valid(section, sizeof(*section)) ||
	    vmm_snapshot_ranges_overlap(section, sizeof(*section), reader,
	    sizeof(*reader)) ||
	    reader->buffer == NULL ||
	    !vmm_snapshot_range_valid(reader->buffer, reader->length) ||
	    reader->sections_read > reader->section_count ||
	    reader->cursor > reader->length ||
	    vmm_snapshot_ranges_overlap(section, sizeof(*section),
	    reader->buffer, reader->length))
		return (EINVAL);
	error = vmm_snapshot_envelope_validate(reader->buffer, reader->length,
	    &section_count);
	if (error != 0 || section_count != reader->section_count)
		return (EINVAL);
	error = vmm_snapshot_envelope_cursor(reader->buffer, reader->length,
	    reader->sections_read, &expected_cursor);
	if (error != 0 || reader->cursor != expected_cursor)
		return (EINVAL);
	if (reader->sections_read == reader->section_count) {
		if (reader->cursor != reader->length)
			return (EINVAL);
		return (ENOENT);
	}
	if (VMM_SNAPSHOT_SECTION_HEADER_SIZE >
	    reader->length - reader->cursor)
		return (EINVAL);
	wire = reader->buffer + reader->cursor;
	payload_length = le32dec(wire + 4);
	if (le16dec(wire) == 0 ||
	    (le16dec(wire + 2) & ~VMM_SNAPSHOT_SECTION_F_VALID) != 0 ||
	    le32dec(wire + 12) != 0 || le32dec(wire + 16) != 0 ||
	    le32dec(wire + 20) != 0 ||
	    payload_length > reader->length - reader->cursor -
	    VMM_SNAPSHOT_SECTION_HEADER_SIZE)
		return (EINVAL);
	candidate = (struct vmm_snapshot_section) {
		.type = le16dec(wire),
		.flags = le16dec(wire + 2),
		.payload_length = payload_length,
		.instance = le32dec(wire + 8),
		.payload = wire + VMM_SNAPSHOT_SECTION_HEADER_SIZE,
	};
	reader->cursor += VMM_SNAPSHOT_SECTION_HEADER_SIZE +
	    candidate.payload_length;
	reader->sections_read++;
	*section = candidate;
	return (0);
}

int
vmm_snapshot_section_skip_unknown(const struct vmm_snapshot_section *section)
{

	if (section == NULL ||
	    !vmm_snapshot_range_valid(section, sizeof(*section)) ||
	    !vmm_snapshot_range_valid(section->payload, section->payload_length) ||
	    section->type == 0 ||
	    (section->flags & ~VMM_SNAPSHOT_SECTION_F_VALID) != 0 ||
	    (section->payload == NULL && section->payload_length != 0))
		return (EINVAL);
	if ((section->flags & VMM_SNAPSHOT_SECTION_F_CRITICAL) != 0)
		return (EPROTONOSUPPORT);
	return (0);
}
