/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>

#include "disk.h"
#include "store.h"

#define	STORE_NAMESPACE_SHIFT	56
#define	STORE_OBJECT_MASK	((1ULL << STORE_NAMESPACE_SHIFT) - 1)

struct filesystem_store {
	struct scratch_store	*scratch;
	struct disk_store	*persistent;
	struct disk_store	*bundle;
};

static struct filesystemcmp_handle
encode(struct filesystemcmp_handle handle, uint32_t namespace_id)
{

	handle.object |= (uint64_t)namespace_id << STORE_NAMESPACE_SHIFT;
	return (handle);
}

static int
decode(struct filesystem_store *store, struct filesystemcmp_handle encoded,
    uint32_t *namespace_id, struct filesystemcmp_handle *handle)
{

	*namespace_id = (uint32_t)(encoded.object >> STORE_NAMESPACE_SHIFT);
	handle->object = encoded.object & STORE_OBJECT_MASK;
	handle->generation = encoded.generation;
	if (*namespace_id < FILESYSTEMCMP_NAMESPACE_SCRATCH ||
	    *namespace_id > FILESYSTEMCMP_NAMESPACE_BUNDLE ||
	    handle->object == 0 ||
	    (*namespace_id == FILESYSTEMCMP_NAMESPACE_PERSISTENT &&
	    store->persistent == NULL) ||
	    (*namespace_id == FILESYSTEMCMP_NAMESPACE_BUNDLE &&
	    store->bundle == NULL)) {
		errno = ESTALE;
		return (-1);
	}
	return (0);
}

int
filesystem_store_create(const struct scratch_limits *limits, int persistent_fd,
    int bundle_fd, struct filesystem_store **storep)
{
	struct filesystem_store *store;
	int error;

	if (limits == NULL || storep == NULL) {
		errno = EINVAL;
		return (-1);
	}
	store = calloc(1, sizeof(*store));
	if (store == NULL)
		return (-1);
	if (scratch_store_create(limits, &store->scratch) == -1 ||
	    (persistent_fd >= 0 &&
	    disk_store_create(persistent_fd, false, limits->max_bytes,
	    limits->max_objects, limits->max_file_bytes,
	    &store->persistent) == -1) ||
	    (bundle_fd >= 0 &&
	    disk_store_create(bundle_fd, true, UINT64_MAX, limits->max_objects,
	    UINT32_MAX, &store->bundle) == -1)) {
		error = errno;
		filesystem_store_destroy(store);
		errno = error;
		return (-1);
	}
	*storep = store;
	return (0);
}

void
filesystem_store_destroy(struct filesystem_store *store)
{

	if (store == NULL)
		return;
	scratch_store_destroy(store->scratch);
	disk_store_destroy(store->persistent);
	disk_store_destroy(store->bundle);
	free(store);
}

uint32_t
filesystem_store_features(const struct filesystem_store *store)
{
	uint32_t features;

	features = FILESYSTEMCMP_FEATURE_INLINE_IO;
	if (store->persistent != NULL)
		features |= FILESYSTEMCMP_FEATURE_PERSISTENT;
	if (store->bundle != NULL)
		features |= FILESYSTEMCMP_FEATURE_BUNDLE;
	return (features);
}

int
filesystem_store_root(struct filesystem_store *store, uint32_t namespace_id,
    struct filesystemcmp_handle *handle)
{
	int result;

	if (store == NULL || handle == NULL) {
		errno = EINVAL;
		return (-1);
	}
	switch (namespace_id) {
	case FILESYSTEMCMP_NAMESPACE_SCRATCH:
		result = scratch_root(store->scratch, handle);
		break;
	case FILESYSTEMCMP_NAMESPACE_PERSISTENT:
		result = store->persistent == NULL ? -1 :
		    disk_root(store->persistent, handle);
		break;
	case FILESYSTEMCMP_NAMESPACE_BUNDLE:
		result = store->bundle == NULL ? -1 :
		    disk_root(store->bundle, handle);
		break;
	default:
		errno = EINVAL;
		return (-1);
	}
	if (result == -1) {
		if (errno == 0)
			errno = ENOENT;
		return (-1);
	}
	*handle = encode(*handle, namespace_id);
	return (0);
}

int
filesystem_store_lookup(struct filesystem_store *store,
    struct filesystemcmp_handle encoded, const void *name, size_t length,
    struct filesystemcmp_handle *result)
{
	struct filesystemcmp_handle handle;
	uint32_t namespace_id;
	int rv;

	if (store == NULL || result == NULL ||
	    decode(store, encoded, &namespace_id, &handle) == -1)
		return (-1);
	if (namespace_id == FILESYSTEMCMP_NAMESPACE_SCRATCH)
		rv = scratch_lookup(store->scratch, handle, name, length, result);
	else
		rv = disk_lookup(namespace_id == FILESYSTEMCMP_NAMESPACE_PERSISTENT ?
		    store->persistent : store->bundle, handle, name, length,
		    result);
	if (rv == 0)
		*result = encode(*result, namespace_id);
	return (rv);
}

int
filesystem_store_create_object(struct filesystem_store *store,
    struct filesystemcmp_handle encoded, const void *name, size_t length,
    uint32_t flags, uint32_t mode, struct filesystemcmp_handle *result)
{
	struct filesystemcmp_handle handle;
	uint32_t namespace_id;
	int rv;

	if (store == NULL || result == NULL ||
	    decode(store, encoded, &namespace_id, &handle) == -1)
		return (-1);
	if (namespace_id == FILESYSTEMCMP_NAMESPACE_SCRATCH)
		rv = scratch_create(store->scratch, handle, name, length, flags,
		    mode, result);
	else
		rv = disk_create(namespace_id == FILESYSTEMCMP_NAMESPACE_PERSISTENT ?
		    store->persistent : store->bundle, handle, name, length,
		    flags, mode, result);
	if (rv == 0)
		*result = encode(*result, namespace_id);
	return (rv);
}

int
filesystem_store_open(struct filesystem_store *store,
    struct filesystemcmp_handle encoded, uint32_t flags)
{
	struct filesystemcmp_handle handle;
	uint32_t namespace_id;

	if (store == NULL ||
	    decode(store, encoded, &namespace_id, &handle) == -1)
		return (-1);
	if (namespace_id == FILESYSTEMCMP_NAMESPACE_SCRATCH)
		return (scratch_open(store->scratch, handle, flags));
	return (disk_open(namespace_id == FILESYSTEMCMP_NAMESPACE_PERSISTENT ?
	    store->persistent : store->bundle, handle, flags));
}

ssize_t
filesystem_store_read(struct filesystem_store *store,
    struct filesystemcmp_handle encoded, uint64_t offset, void *buffer,
    size_t length)
{
	struct filesystemcmp_handle handle;
	uint32_t namespace_id;

	if (store == NULL ||
	    decode(store, encoded, &namespace_id, &handle) == -1)
		return (-1);
	if (namespace_id == FILESYSTEMCMP_NAMESPACE_SCRATCH)
		return (scratch_read(store->scratch, handle, offset, buffer,
		    length));
	return (disk_read(namespace_id == FILESYSTEMCMP_NAMESPACE_PERSISTENT ?
	    store->persistent : store->bundle, handle, offset, buffer, length));
}

ssize_t
filesystem_store_write(struct filesystem_store *store,
    struct filesystemcmp_handle encoded, uint64_t offset, const void *buffer,
    size_t length)
{
	struct filesystemcmp_handle handle;
	uint32_t namespace_id;

	if (store == NULL ||
	    decode(store, encoded, &namespace_id, &handle) == -1)
		return (-1);
	if (namespace_id == FILESYSTEMCMP_NAMESPACE_SCRATCH)
		return (scratch_write(store->scratch, handle, offset, buffer,
		    length));
	return (disk_write(namespace_id == FILESYSTEMCMP_NAMESPACE_PERSISTENT ?
	    store->persistent : store->bundle, handle, offset, buffer, length));
}

int
filesystem_store_stat(struct filesystem_store *store,
    struct filesystemcmp_handle encoded, struct filesystemcmp_stat_reply *reply)
{
	struct filesystemcmp_handle handle;
	uint32_t namespace_id;

	if (store == NULL ||
	    decode(store, encoded, &namespace_id, &handle) == -1)
		return (-1);
	if (namespace_id == FILESYSTEMCMP_NAMESPACE_SCRATCH)
		return (scratch_stat(store->scratch, handle, reply));
	return (disk_stat(namespace_id == FILESYSTEMCMP_NAMESPACE_PERSISTENT ?
	    store->persistent : store->bundle, handle, reply));
}

int
filesystem_store_unlink(struct filesystem_store *store,
    struct filesystemcmp_handle encoded, const void *name, size_t length)
{
	struct filesystemcmp_handle handle;
	uint32_t namespace_id;

	if (store == NULL ||
	    decode(store, encoded, &namespace_id, &handle) == -1)
		return (-1);
	if (namespace_id == FILESYSTEMCMP_NAMESPACE_SCRATCH)
		return (scratch_unlink(store->scratch, handle, name, length));
	return (disk_unlink(namespace_id == FILESYSTEMCMP_NAMESPACE_PERSISTENT ?
	    store->persistent : store->bundle, handle, name, length));
}

int
filesystem_store_rename(struct filesystem_store *store,
    struct filesystemcmp_handle old_encoded, const void *old_name,
    size_t old_length, struct filesystemcmp_handle new_encoded,
    const void *new_name, size_t new_length)
{
	struct filesystemcmp_handle old_handle, new_handle;
	uint32_t old_namespace, new_namespace;

	if (store == NULL ||
	    decode(store, old_encoded, &old_namespace, &old_handle) == -1 ||
	    decode(store, new_encoded, &new_namespace, &new_handle) == -1)
		return (-1);
	if (old_namespace != new_namespace) {
		errno = EXDEV;
		return (-1);
	}
	if (old_namespace == FILESYSTEMCMP_NAMESPACE_SCRATCH)
		return (scratch_rename(store->scratch, old_handle, old_name,
		    old_length, new_handle, new_name, new_length));
	return (disk_rename(old_namespace ==
	    FILESYSTEMCMP_NAMESPACE_PERSISTENT ? store->persistent :
	    store->bundle, old_handle, old_name, old_length, new_handle,
	    new_name, new_length));
}

int
filesystem_store_close(struct filesystem_store *store,
    struct filesystemcmp_handle encoded)
{
	struct filesystemcmp_handle handle;
	uint32_t namespace_id;

	if (store == NULL ||
	    decode(store, encoded, &namespace_id, &handle) == -1)
		return (-1);
	if (namespace_id == FILESYSTEMCMP_NAMESPACE_SCRATCH)
		return (0);
	return (disk_close(namespace_id == FILESYSTEMCMP_NAMESPACE_PERSISTENT ?
	    store->persistent : store->bundle, handle));
}

int
filesystem_store_sync(struct filesystem_store *store,
    struct filesystemcmp_handle encoded)
{
	struct filesystemcmp_handle handle;
	uint32_t namespace_id;

	if (store == NULL ||
	    decode(store, encoded, &namespace_id, &handle) == -1)
		return (-1);
	if (namespace_id == FILESYSTEMCMP_NAMESPACE_SCRATCH ||
	    namespace_id == FILESYSTEMCMP_NAMESPACE_BUNDLE)
		return (0);
	return (disk_sync(store->persistent, handle));
}

int
filesystem_store_dup(struct filesystem_store *store,
    struct filesystemcmp_handle encoded, struct filesystemcmp_handle *result)
{
	struct filesystemcmp_handle handle;
	uint32_t namespace_id;
	int rv;

	if (store == NULL || result == NULL ||
	    decode(store, encoded, &namespace_id, &handle) == -1)
		return (-1);
	if (namespace_id == FILESYSTEMCMP_NAMESPACE_SCRATCH) {
		*result = encoded;
		return (0);
	}
	rv = disk_dup(namespace_id == FILESYSTEMCMP_NAMESPACE_PERSISTENT ?
	    store->persistent : store->bundle, handle, result);
	if (rv == 0)
		*result = encode(*result, namespace_id);
	return (rv);
}
