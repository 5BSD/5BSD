/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/endian.h>

#include <errno.h>
#include <sha256.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "checkpoint_machine.h"

static int
checkpoint_machine_device_compare(const void *left, const void *right)
{
	const struct checkpoint_machine_device * const *a, * const *b;

	a = left;
	b = right;
	return (strcmp((*a)->name, (*b)->name));
}

static bool
checkpoint_machine_shape_canonical(const char *shape, size_t capacity)
{
	const char *terminator;
	size_t used;

	terminator = memchr(shape, '\0', capacity);
	if (terminator == NULL)
		return (false);
	used = (size_t)(terminator - shape) + 1;
	for (size_t i = used; i < capacity; i++) {
		if (shape[i] != '\0')
			return (false);
	}
	return (true);
}

static void
checkpoint_machine_hash_u32(SHA256_CTX *context, uint32_t value)
{
	uint8_t encoded[4];

	le32enc(encoded, value);
	SHA256_Update(context, encoded, sizeof(encoded));
}

static void
checkpoint_machine_hash_u64(SHA256_CTX *context, uint64_t value)
{
	uint8_t encoded[8];

	le64enc(encoded, value);
	SHA256_Update(context, encoded, sizeof(encoded));
}

static int
checkpoint_machine_hash_string(SHA256_CTX *context, const char *value,
    size_t maximum)
{
	size_t length;

	if (value == NULL)
		return (EINVAL);
	length = strnlen(value, maximum);
	if (length == maximum || length > UINT32_MAX)
		return (EINVAL);
	checkpoint_machine_hash_u32(context, (uint32_t)length);
	SHA256_Update(context, value, length);
	return (0);
}

bool
checkpoint_machine_digest_canonical(const char *digest)
{

	if (digest == NULL ||
	    strnlen(digest, CHECKPOINT_MACHINE_DIGEST_LENGTH) !=
	    CHECKPOINT_MACHINE_DIGEST_LENGTH - 1)
		return (false);
	for (size_t i = 0; i < CHECKPOINT_MACHINE_DIGEST_LENGTH - 1; i++) {
		if (!((digest[i] >= '0' && digest[i] <= '9') ||
		    (digest[i] >= 'a' && digest[i] <= 'f')))
			return (false);
	}
	return (true);
}

int
checkpoint_machine_topology_digest(
    const struct checkpoint_machine_device *devices, size_t count,
    char *digest, size_t capacity)
{
	const struct checkpoint_machine_device **ordered;
	const struct pci_snapshot_compat *compat;
	SHA256_CTX context;
	char staging[CHECKPOINT_MACHINE_DIGEST_LENGTH];
	int error;

	if ((count != 0 && devices == NULL) || digest == NULL ||
	    capacity < CHECKPOINT_MACHINE_DIGEST_LENGTH || count > UINT32_MAX)
		return (EINVAL);
	ordered = calloc(count, sizeof(*ordered));
	if (count != 0 && ordered == NULL)
		return (ENOMEM);
	for (size_t i = 0; i < count; i++) {
		if (devices[i].name == NULL || devices[i].name[0] == '\0' ||
		    strnlen(devices[i].name,
		    CHECKPOINT_MACHINE_DEVICE_NAME_MAX + 1) >
		    CHECKPOINT_MACHINE_DEVICE_NAME_MAX) {
			error = EINVAL;
			goto out;
		}
		ordered[i] = &devices[i];
	}
	/*
	 * count == 0 deliberately permits a NULL devices/ordered pointer.  Avoid
	 * relying on a libc extension which accepts a NULL qsort base for an empty
	 * array; the empty topology has a canonical digest without sorting.
	 */
	if (count > 1) {
		qsort(ordered, count, sizeof(*ordered),
		    checkpoint_machine_device_compare);
	}
	for (size_t i = 1; i < count; i++) {
		if (strcmp(ordered[i - 1]->name, ordered[i]->name) == 0) {
			error = EEXIST;
			goto out;
		}
	}

	SHA256_Init(&context);
	checkpoint_machine_hash_u32(&context,
	    CHECKPOINT_MACHINE_TOPOLOGY_VERSION);
	checkpoint_machine_hash_u32(&context, (uint32_t)count);
	for (size_t i = 0; i < count; i++) {
		error = checkpoint_machine_hash_string(&context,
		    ordered[i]->name, CHECKPOINT_MACHINE_DEVICE_NAME_MAX + 1);
		if (error != 0)
			goto out;
		compat = ordered[i]->compat;
		checkpoint_machine_hash_u32(&context, compat != NULL ? 1 : 0);
		if (compat == NULL)
			continue;
		if (compat->schema != PCI_SNAPSHOT_COMPAT_SCHEMA ||
		    !checkpoint_machine_shape_canonical(compat->queue_sizes,
		    sizeof(compat->queue_sizes)) ||
		    !checkpoint_machine_shape_canonical(compat->shared_memory,
		    sizeof(compat->shared_memory))) {
			error = EINVAL;
			goto out;
		}
		checkpoint_machine_hash_u32(&context, compat->schema);
		checkpoint_machine_hash_u32(&context, compat->transport);
		checkpoint_machine_hash_u32(&context, compat->queue_count);
		checkpoint_machine_hash_u32(&context,
		    compat->msix_table_count);
		checkpoint_machine_hash_u64(&context, compat->config_size);
		error = checkpoint_machine_hash_string(&context,
		    compat->queue_sizes, sizeof(compat->queue_sizes));
		if (error != 0)
			goto out;
		error = checkpoint_machine_hash_string(&context,
		    compat->shared_memory, sizeof(compat->shared_memory));
		if (error != 0)
			goto out;
	}
	if (SHA256_End(&context, staging) == NULL) {
		error = EIO;
		goto out;
	}
	memmove(digest, staging, sizeof(staging));
	error = 0;
out:
	free(ordered);
	return (error);
}
