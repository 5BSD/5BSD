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

/*
 * Compare two records exactly, such as the checkpoint metadata ("source")
 * against a payload's own envelope ("destination").  When they differ,
 * reason (which may be NULL when reasonlen is 0) names the first field.
 */
bool
checkpoint_compat_equal(const struct pci_snapshot_compat *left,
    const struct pci_snapshot_compat *right, char *reason, size_t reasonlen)
{

	if (reasonlen != 0)
		reason[0] = '\0';
	if (left == NULL || right == NULL)
		return (false);
	if (!checkpoint_compat_string_is_canonical(left->queue_sizes,
	    sizeof(left->queue_sizes)) ||
	    !checkpoint_compat_string_is_canonical(left->shared_memory,
	    sizeof(left->shared_memory)) ||
	    !checkpoint_compat_string_is_canonical(right->queue_sizes,
	    sizeof(right->queue_sizes)) ||
	    !checkpoint_compat_string_is_canonical(right->shared_memory,
	    sizeof(right->shared_memory))) {
		snprintf(reason, reasonlen, "queue_sizes or shared_memory: not "
		    "a canonical shape");
		return (false);
	}
	return (!pci_snapshot_compat_field_differs("schema", left->schema,
	    right->schema, reason, reasonlen) &&
	    !pci_snapshot_compat_field_differs("transport", left->transport,
	    right->transport, reason, reasonlen) &&
	    !pci_snapshot_compat_field_differs("queue_count",
	    left->queue_count, right->queue_count, reason, reasonlen) &&
	    !pci_snapshot_compat_field_differs("msix_table_count",
	    left->msix_table_count, right->msix_table_count, reason,
	    reasonlen) &&
	    !pci_snapshot_compat_field_differs("config_size",
	    left->config_size, right->config_size, reason, reasonlen) &&
	    !pci_snapshot_compat_shape_differs("queue_sizes", left->queue_sizes,
	    right->queue_sizes, reason, reasonlen) &&
	    !pci_snapshot_compat_shape_differs("shared_memory",
	    left->shared_memory, right->shared_memory, reason, reasonlen) &&
	    !pci_snapshot_compat_field_differs("offered_features",
	    left->offered_features, right->offered_features, reason,
	    reasonlen) &&
	    !pci_snapshot_compat_field_differs("negotiated_features",
	    left->negotiated_features, right->negotiated_features, reason,
	    reasonlen) &&
	    !pci_snapshot_compat_field_differs("payload_crc32",
	    left->payload_crc32, right->payload_crc32, reason, reasonlen));
}
