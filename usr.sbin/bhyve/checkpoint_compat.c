/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/endian.h>

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <zlib.h>

#include "checkpoint_compat.h"

static bool
checkpoint_compat_string_is_canonical(const char *string, size_t capacity)
{
	const char *terminator;
	size_t used;

	terminator = memchr(string, '\0', capacity);
	if (terminator == NULL)
		return (false);
	used = (size_t)(terminator - string) + 1;
	for (size_t i = used; i < capacity; i++) {
		if (string[i] != '\0')
			return (false);
	}
	return (true);
}

int
checkpoint_compat_encode(const struct pci_snapshot_compat *compat,
    void *record, size_t capacity)
{
	uint8_t staging[CHECKPOINT_COMPAT_ENVELOPE_SIZE];
	uint8_t *buffer;

	if (compat == NULL || record == NULL ||
	    capacity < CHECKPOINT_COMPAT_ENVELOPE_SIZE ||
	    compat->schema != PCI_SNAPSHOT_COMPAT_SCHEMA ||
	    (compat->negotiated_features & ~compat->offered_features) != 0 ||
	    !checkpoint_compat_string_is_canonical(compat->queue_sizes,
	    sizeof(compat->queue_sizes)) ||
	    !checkpoint_compat_string_is_canonical(compat->shared_memory,
	    sizeof(compat->shared_memory)))
		return (EINVAL);
	buffer = staging;
	memset(buffer, 0, sizeof(staging));
	le32enc(buffer + 0, CHECKPOINT_COMPAT_MAGIC);
	le32enc(buffer + 4, compat->schema);
	le32enc(buffer + 8, compat->transport);
	le32enc(buffer + 12, compat->queue_count);
	le32enc(buffer + 16, compat->msix_table_count);
	le64enc(buffer + 20, compat->config_size);
	le64enc(buffer + 28, compat->offered_features);
	le64enc(buffer + 36, compat->negotiated_features);
	le32enc(buffer + 44, compat->payload_crc32);
	memcpy(buffer + CHECKPOINT_COMPAT_SCALARS_SIZE, compat->queue_sizes,
	    sizeof(compat->queue_sizes));
	memcpy(buffer + CHECKPOINT_COMPAT_SCALARS_SIZE +
	    sizeof(compat->queue_sizes), compat->shared_memory,
	    sizeof(compat->shared_memory));
	memmove(record, staging, sizeof(staging));
	return (0);
}

int
checkpoint_compat_decode(const void *record, size_t record_size,
    struct pci_snapshot_compat *compat)
{
	struct pci_snapshot_compat candidate;
	const uint8_t *buffer;

	if (record == NULL || compat == NULL ||
	    record_size < CHECKPOINT_COMPAT_ENVELOPE_SIZE)
		return (EINVAL);
	buffer = record;
	if (le32dec(buffer + 0) != CHECKPOINT_COMPAT_MAGIC)
		return (EINVAL);
	memset(&candidate, 0, sizeof(candidate));
	candidate.schema = le32dec(buffer + 4);
	candidate.transport = le32dec(buffer + 8);
	candidate.queue_count = le32dec(buffer + 12);
	candidate.msix_table_count = le32dec(buffer + 16);
	candidate.config_size = le64dec(buffer + 20);
	candidate.offered_features = le64dec(buffer + 28);
	candidate.negotiated_features = le64dec(buffer + 36);
	candidate.payload_crc32 = le32dec(buffer + 44);
	memcpy(candidate.queue_sizes,
	    buffer + CHECKPOINT_COMPAT_SCALARS_SIZE,
	    sizeof(candidate.queue_sizes));
	memcpy(candidate.shared_memory,
	    buffer + CHECKPOINT_COMPAT_SCALARS_SIZE +
	    sizeof(candidate.queue_sizes), sizeof(candidate.shared_memory));
	if (candidate.schema != PCI_SNAPSHOT_COMPAT_SCHEMA ||
	    (candidate.negotiated_features & ~candidate.offered_features) != 0 ||
	    !checkpoint_compat_string_is_canonical(candidate.queue_sizes,
	    sizeof(candidate.queue_sizes)) ||
	    !checkpoint_compat_string_is_canonical(candidate.shared_memory,
	    sizeof(candidate.shared_memory)))
		return (EINVAL);
	memmove(compat, &candidate, sizeof(candidate));
	return (0);
}

uint32_t
checkpoint_compat_payload_crc32(const void *payload, size_t payload_size)
{
	const uint8_t *cursor;
	uLong checksum;
	uInt chunk;

	if (payload == NULL && payload_size != 0)
		return (0);
	cursor = payload;
	checksum = crc32(0L, Z_NULL, 0);
	while (payload_size != 0) {
		chunk = payload_size > UINT_MAX ? UINT_MAX : (uInt)payload_size;
		checksum = crc32(checksum, cursor, chunk);
		cursor += chunk;
		payload_size -= chunk;
	}
	return ((uint32_t)checksum);
}

bool
checkpoint_compat_equal(const struct pci_snapshot_compat *left,
    const struct pci_snapshot_compat *right)
{

	return (left != NULL && right != NULL &&
	    checkpoint_compat_string_is_canonical(left->queue_sizes,
	    sizeof(left->queue_sizes)) &&
	    checkpoint_compat_string_is_canonical(left->shared_memory,
	    sizeof(left->shared_memory)) &&
	    checkpoint_compat_string_is_canonical(right->queue_sizes,
	    sizeof(right->queue_sizes)) &&
	    checkpoint_compat_string_is_canonical(right->shared_memory,
	    sizeof(right->shared_memory)) &&
	    left->schema == right->schema &&
	    left->transport == right->transport &&
	    left->queue_count == right->queue_count &&
	    left->msix_table_count == right->msix_table_count &&
	    left->config_size == right->config_size &&
	    left->offered_features == right->offered_features &&
	    left->negotiated_features == right->negotiated_features &&
	    left->payload_crc32 == right->payload_crc32 &&
	    memcmp(left->queue_sizes, right->queue_sizes,
	    sizeof(left->queue_sizes)) == 0 &&
	    memcmp(left->shared_memory, right->shared_memory,
	    sizeof(left->shared_memory)) == 0);
}

/*
 * Name the first compatibility field on which a restore refused a device,
 * for the restore log.  With "exact", every field must be equal (the
 * checkpoint metadata against the payload's own envelope); otherwise the
 * rules of pci_snapshot_compat_validate() apply (source against the
 * destination device).  Returns 0 with an empty string when nothing differs.
 */
int
checkpoint_compat_describe_mismatch(const struct pci_snapshot_compat *source,
    const struct pci_snapshot_compat *destination, bool exact, char *buf,
    size_t len)
{
	const struct pci_snapshot_compat *s, *d;

	if (buf == NULL || len == 0)
		return (EINVAL);
	buf[0] = '\0';
	if (source == NULL || destination == NULL)
		return (EINVAL);
	s = source;
	d = destination;
#define	DESCRIBE_COMPAT_FIELD(field)					\
	if (s->field != d->field) {					\
		snprintf(buf, len, #field ": source %#jx, destination %#jx",\
		    (uintmax_t)s->field, (uintmax_t)d->field);		\
		return (ENOTSUP);					\
	}
#define	DESCRIBE_COMPAT_SHAPE(field)					\
	if (!checkpoint_compat_string_is_canonical(s->field,		\
	    sizeof(s->field)) ||					\
	    !checkpoint_compat_string_is_canonical(d->field,		\
	    sizeof(d->field))) {					\
		snprintf(buf, len, #field ": not a canonical shape");	\
		return (EINVAL);					\
	}								\
	if (memcmp(s->field, d->field, sizeof(s->field)) != 0) {	\
		snprintf(buf, len, #field ": source \"%.*s\", "		\
		    "destination \"%.*s\"", (int)sizeof(s->field),	\
		    s->field, (int)sizeof(d->field), d->field);		\
		return (ENOTSUP);					\
	}
	if (exact) {
		DESCRIBE_COMPAT_FIELD(schema)
	} else if (s->schema != PCI_SNAPSHOT_COMPAT_SCHEMA ||
	    d->schema != PCI_SNAPSHOT_COMPAT_SCHEMA) {
		snprintf(buf, len, "schema: source %u, destination %u, "
		    "supported %u", s->schema, d->schema,
		    PCI_SNAPSHOT_COMPAT_SCHEMA);
		return (EINVAL);
	}
	if (!exact && (s->negotiated_features & ~s->offered_features) != 0) {
		snprintf(buf, len, "negotiated_features: source negotiated "
		    "%#jx which it did not offer (offered %#jx)",
		    (uintmax_t)(s->negotiated_features & ~s->offered_features),
		    (uintmax_t)s->offered_features);
		return (EINVAL);
	}
	DESCRIBE_COMPAT_FIELD(transport)
	DESCRIBE_COMPAT_FIELD(queue_count)
	DESCRIBE_COMPAT_FIELD(msix_table_count)
	DESCRIBE_COMPAT_FIELD(config_size)
	DESCRIBE_COMPAT_SHAPE(queue_sizes)
	DESCRIBE_COMPAT_SHAPE(shared_memory)
	if (exact) {
		DESCRIBE_COMPAT_FIELD(offered_features)
		DESCRIBE_COMPAT_FIELD(negotiated_features)
		DESCRIBE_COMPAT_FIELD(payload_crc32)
		return (0);
	}
#undef DESCRIBE_COMPAT_SHAPE
#undef DESCRIBE_COMPAT_FIELD
	if ((s->offered_features & ~d->offered_features) != 0) {
		snprintf(buf, len, "offered_features: source %#jx, destination "
		    "%#jx (destination lacks %#jx)",
		    (uintmax_t)s->offered_features,
		    (uintmax_t)d->offered_features,
		    (uintmax_t)(s->offered_features & ~d->offered_features));
		return (ENOTSUP);
	}
	if ((s->negotiated_features & ~d->offered_features) != 0) {
		snprintf(buf, len, "negotiated_features: source %#jx, "
		    "destination offers %#jx (lacks %#jx)",
		    (uintmax_t)s->negotiated_features,
		    (uintmax_t)d->offered_features,
		    (uintmax_t)(s->negotiated_features & ~d->offered_features));
		return (ENOTSUP);
	}
	return (0);
}
