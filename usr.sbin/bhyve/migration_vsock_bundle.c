/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/endian.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "migration_vsock_bundle.h"
#include "vsock_migration_state.h"

#define BUNDLE_MAGIC 0x31425356U /* VSB1 */
#define BUNDLE_VERSION 1U
#define BUNDLE_HEADER_SIZE 16U
#define BUNDLE_ITEM_SIZE 48U

static bool
bundle_name_valid(const char name[MIGRATION_VSOCK_BUNDLE_NAME])
{
	size_t end;

	if (name[0] == '\0')
		return (false);
	end = strnlen(name, MIGRATION_VSOCK_BUNDLE_NAME);
	if (end == MIGRATION_VSOCK_BUNDLE_NAME)
		return (false);
	for (size_t i = end + 1; i < MIGRATION_VSOCK_BUNDLE_NAME; i++) {
		if (name[i] != '\0')
			return (false);
	}
	return (true);
}

static int
bundle_item_validate(const struct migration_vsock_bundle_item *item,
    uint32_t *endpoint_count)
{
	struct vsock_migration_conn_state states[VSOCK_MIGRATION_MAX_CONNS];
	uint32_t count;
	int error;

	if (item == NULL || !bundle_name_valid(item->name) ||
	    item->table == NULL || item->table_len == 0 ||
	    item->table_len > VSOCK_MIGRATION_MAX_TABLE_SIZE)
		return (EINVAL);
	error = vsock_migration_table_decode(item->table, item->table_len,
	    states, VSOCK_MIGRATION_MAX_CONNS, &count);
	if (error != 0)
		return (error);
	if (item->endpoint_count != count)
		return (EINVAL);
	*endpoint_count = count;
	return (0);
}

int
migration_vsock_bundle_size(const struct migration_vsock_bundle_item *items,
    uint32_t count, size_t *size_out)
{
	size_t total;
	uint32_t endpoints, this_count;
	int error;

	if (size_out == NULL || count > MIGRATION_VSOCK_BUNDLE_MAX_DEVICES ||
	    (count != 0 && items == NULL))
		return (EINVAL);
	total = BUNDLE_HEADER_SIZE;
	endpoints = 0;
	for (uint32_t i = 0; i < count; i++) {
		error = bundle_item_validate(&items[i], &this_count);
		if (error != 0)
			return (error);
		if (this_count > MIGRATION_VSOCK_BUNDLE_MAX_ENDPOINTS - endpoints)
			return (EFBIG);
		endpoints += this_count;
		if (total > MIGRATION_VSOCK_BUNDLE_MAX_WIRE -
		    BUNDLE_ITEM_SIZE ||
		    items[i].table_len > MIGRATION_VSOCK_BUNDLE_MAX_WIRE -
		    total - BUNDLE_ITEM_SIZE)
			return (EFBIG);
		total += BUNDLE_ITEM_SIZE + items[i].table_len;
		for (uint32_t j = 0; j < i; j++) {
			if (memcmp(items[i].name, items[j].name,
			    MIGRATION_VSOCK_BUNDLE_NAME) == 0)
				return (EINVAL);
		}
	}
	*size_out = total;
	return (0);
}

int
migration_vsock_bundle_encode(const struct migration_vsock_bundle_item *items,
    uint32_t count, uint8_t *wire, size_t wire_size)
{
	size_t total, offset;
	int error;

	if (wire == NULL)
		return (EINVAL);
	error = migration_vsock_bundle_size(items, count, &total);
	if (error != 0)
		return (error);
	if (wire_size < total)
		return (EMSGSIZE);
	le32enc(wire, BUNDLE_MAGIC);
	le32enc(wire + 4, BUNDLE_VERSION);
	le32enc(wire + 8, (uint32_t)total);
	le32enc(wire + 12, count);
	offset = BUNDLE_HEADER_SIZE;
	for (uint32_t i = 0; i < count; i++) {
		memcpy(wire + offset, items[i].name,
		    MIGRATION_VSOCK_BUNDLE_NAME);
		le32enc(wire + offset + 40, (uint32_t)items[i].table_len);
		le32enc(wire + offset + 44, items[i].endpoint_count);
		offset += BUNDLE_ITEM_SIZE;
		memcpy(wire + offset, items[i].table, items[i].table_len);
		offset += items[i].table_len;
	}
	return (0);
}

int
migration_vsock_bundle_decode(const uint8_t *wire, size_t wire_size,
    struct migration_vsock_bundle_item *items, uint32_t capacity,
    uint32_t *count_out, uint32_t *endpoints_out)
{
	struct migration_vsock_bundle_item candidate;
	struct migration_vsock_bundle_item
	    decoded[MIGRATION_VSOCK_BUNDLE_MAX_DEVICES];
	size_t offset;
	uint32_t count, endpoints, this_count;
	int error;

	if (wire == NULL || count_out == NULL || endpoints_out == NULL ||
	    wire_size < BUNDLE_HEADER_SIZE ||
	    wire_size > MIGRATION_VSOCK_BUNDLE_MAX_WIRE ||
	    le32dec(wire) != BUNDLE_MAGIC ||
	    le32dec(wire + 4) != BUNDLE_VERSION ||
	    le32dec(wire + 8) != wire_size)
		return (EINVAL);
	count = le32dec(wire + 12);
	if (count > MIGRATION_VSOCK_BUNDLE_MAX_DEVICES ||
	    count > capacity || (count != 0 && items == NULL))
		return (EINVAL);
	offset = BUNDLE_HEADER_SIZE;
	endpoints = 0;
	for (uint32_t i = 0; i < count; i++) {
		if (wire_size - offset < BUNDLE_ITEM_SIZE)
			return (EINVAL);
		memset(&candidate, 0, sizeof(candidate));
		memcpy(candidate.name, wire + offset,
		    MIGRATION_VSOCK_BUNDLE_NAME);
		candidate.table_len = le32dec(wire + offset + 40);
		candidate.endpoint_count = le32dec(wire + offset + 44);
		offset += BUNDLE_ITEM_SIZE;
		if (candidate.table_len > wire_size - offset)
			return (EINVAL);
		candidate.table = wire + offset;
		error = bundle_item_validate(&candidate, &this_count);
		if (error != 0)
			return (error);
		if (this_count > MIGRATION_VSOCK_BUNDLE_MAX_ENDPOINTS - endpoints)
			return (EFBIG);
		endpoints += this_count;
		for (uint32_t j = 0; j < i; j++) {
			if (memcmp(candidate.name, decoded[j].name,
			    MIGRATION_VSOCK_BUNDLE_NAME) == 0)
				return (EINVAL);
		}
		decoded[i] = candidate;
		offset += candidate.table_len;
	}
	if (offset != wire_size)
		return (EINVAL);
	if (count != 0)
		memcpy(items, decoded, count * sizeof(decoded[0]));
	*count_out = count;
	*endpoints_out = endpoints;
	return (0);
}
