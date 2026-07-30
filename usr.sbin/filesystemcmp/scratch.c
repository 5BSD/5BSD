/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/stat.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "scratch.h"

struct scratch_object {
	uint64_t	generation;
	uint64_t	parent;
	uint64_t	mtime;
	uint8_t		*data;
	size_t		size;
	size_t		capacity;
	char		name[FILESYSTEMCMP_NAME_MAX + 1];
	uint16_t	name_length;
	uint16_t	mode;
	uint8_t		type;
	bool		live;
};

struct scratch_store {
	struct scratch_limits limits;
	struct scratch_object *objects;
	uint64_t	bytes;
	uint32_t	nobjects;
};

static uint64_t
now_seconds(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_REALTIME, &ts) == -1)
		return (0);
	return ((uint64_t)ts.tv_sec);
}

static int
valid_name(const void *name, size_t length)
{
	const uint8_t *p;
	size_t i;

	if (name == NULL || length == 0 ||
	    length > FILESYSTEMCMP_NAME_MAX ||
	    (length == 1 && memcmp(name, ".", 1) == 0) ||
	    (length == 2 && memcmp(name, "..", 2) == 0))
		return (0);
	p = name;
	for (i = 0; i < length; i++) {
		if (p[i] == '\0' || p[i] == '/')
			return (0);
	}
	return (1);
}

static struct scratch_object *
resolve(struct scratch_store *store, struct filesystemcmp_handle handle)
{
	struct scratch_object *object;

	if (handle.object == 0 || handle.object > store->limits.max_objects) {
		errno = ESTALE;
		return (NULL);
	}
	object = &store->objects[handle.object];
	if (!object->live || object->generation != handle.generation) {
		errno = ESTALE;
		return (NULL);
	}
	return (object);
}

static struct filesystemcmp_handle
make_handle(struct scratch_store *store, struct scratch_object *object)
{
	struct filesystemcmp_handle handle;

	handle.object = (uint64_t)(object - store->objects);
	handle.generation = object->generation;
	return (handle);
}

static struct scratch_object *
find_child(struct scratch_store *store, uint64_t parent, const void *name,
    size_t length)
{
	struct scratch_object *object;
	uint32_t i;

	for (i = 1; i <= store->limits.max_objects; i++) {
		object = &store->objects[i];
		if (object->live && object->parent == parent &&
		    object->name_length == length &&
		    memcmp(object->name, name, length) == 0)
			return (object);
	}
	errno = ENOENT;
	return (NULL);
}

int
scratch_store_create(const struct scratch_limits *limits,
    struct scratch_store **storep)
{
	struct scratch_store *store;

	if (limits == NULL || storep == NULL || limits->max_objects < 1 ||
	    limits->max_objects > 1048576 || limits->max_bytes == 0 ||
	    limits->max_file_bytes == 0 ||
	    limits->max_file_bytes > limits->max_bytes) {
		errno = EINVAL;
		return (-1);
	}
	store = calloc(1, sizeof(*store));
	if (store == NULL)
		return (-1);
	store->objects = calloc((size_t)limits->max_objects + 1,
	    sizeof(*store->objects));
	if (store->objects == NULL) {
		free(store);
		return (-1);
	}
	store->limits = *limits;
	store->objects[1].live = true;
	store->objects[1].generation = 1;
	store->objects[1].type = FILESYSTEMCMP_TYPE_DIRECTORY;
	store->objects[1].mode = 0700;
	store->objects[1].mtime = now_seconds();
	store->nobjects = 1;
	*storep = store;
	return (0);
}

void
scratch_store_destroy(struct scratch_store *store)
{
	uint32_t i;

	if (store == NULL)
		return;
	for (i = 1; i <= store->limits.max_objects; i++) {
		free(store->objects[i].data);
		explicit_bzero(&store->objects[i], sizeof(store->objects[i]));
	}
	free(store->objects);
	explicit_bzero(store, sizeof(*store));
	free(store);
}

int
scratch_root(struct scratch_store *store, struct filesystemcmp_handle *handle)
{

	if (store == NULL || handle == NULL) {
		errno = EINVAL;
		return (-1);
	}
	*handle = make_handle(store, &store->objects[1]);
	return (0);
}

int
scratch_lookup(struct scratch_store *store,
    struct filesystemcmp_handle directory, const void *name, size_t length,
    struct filesystemcmp_handle *handle)
{
	struct scratch_object *dir, *object;

	if (store == NULL || handle == NULL || !valid_name(name, length)) {
		errno = EINVAL;
		return (-1);
	}
	dir = resolve(store, directory);
	if (dir == NULL)
		return (-1);
	if (dir->type != FILESYSTEMCMP_TYPE_DIRECTORY) {
		errno = ENOTDIR;
		return (-1);
	}
	object = find_child(store, directory.object, name, length);
	if (object == NULL)
		return (-1);
	*handle = make_handle(store, object);
	return (0);
}

int
scratch_create(struct scratch_store *store,
    struct filesystemcmp_handle directory, const void *name, size_t length,
    uint32_t flags, uint32_t mode, struct filesystemcmp_handle *handle)
{
	struct scratch_object *dir, *object;
	uint32_t i;

	if (store == NULL || handle == NULL || !valid_name(name, length) ||
	    (flags & ~FILESYSTEMCMP_CREATE_MASK) != 0) {
		errno = EINVAL;
		return (-1);
	}
	dir = resolve(store, directory);
	if (dir == NULL)
		return (-1);
	if (dir->type != FILESYSTEMCMP_TYPE_DIRECTORY) {
		errno = ENOTDIR;
		return (-1);
	}
	object = find_child(store, directory.object, name, length);
	if (object != NULL) {
		if ((flags & FILESYSTEMCMP_CREATE_EXCLUSIVE) != 0) {
			errno = EEXIST;
			return (-1);
		}
		*handle = make_handle(store, object);
		return (0);
	}
	if (errno != ENOENT)
		return (-1);
	if (store->nobjects == store->limits.max_objects) {
		errno = ENOSPC;
		return (-1);
	}
	for (i = 2; i <= store->limits.max_objects; i++)
		if (!store->objects[i].live)
			break;
	object = &store->objects[i];
	object->generation++;
	if (object->generation == 0)
		object->generation = 1;
	object->live = true;
	object->parent = directory.object;
	object->type = (flags & FILESYSTEMCMP_CREATE_DIRECTORY) != 0 ?
	    FILESYSTEMCMP_TYPE_DIRECTORY : FILESYSTEMCMP_TYPE_REGULAR;
	object->mode = (uint16_t)(mode & (object->type ==
	    FILESYSTEMCMP_TYPE_DIRECTORY ? 0700 : 0600));
	object->mtime = now_seconds();
	object->name_length = (uint16_t)length;
	memcpy(object->name, name, length);
	object->name[length] = '\0';
	store->nobjects++;
	*handle = make_handle(store, object);
	return (0);
}

int
scratch_open(struct scratch_store *store,
    struct filesystemcmp_handle handle, uint32_t flags)
{
	struct scratch_object *object;

	if (store == NULL || (flags & ~FILESYSTEMCMP_OPEN_MASK) != 0) {
		errno = EINVAL;
		return (-1);
	}
	object = resolve(store, handle);
	if (object == NULL)
		return (-1);
	if ((flags & FILESYSTEMCMP_OPEN_TRUNCATE) != 0) {
		if (object->type != FILESYSTEMCMP_TYPE_REGULAR) {
			errno = EISDIR;
			return (-1);
		}
		store->bytes -= object->size;
		object->size = 0;
		object->mtime = now_seconds();
	}
	return (0);
}

ssize_t
scratch_read(struct scratch_store *store, struct filesystemcmp_handle handle,
    uint64_t offset, void *buffer, size_t length)
{
	struct scratch_object *object;
	size_t available;

	if (store == NULL || (buffer == NULL && length != 0)) {
		errno = EINVAL;
		return (-1);
	}
	object = resolve(store, handle);
	if (object == NULL)
		return (-1);
	if (object->type != FILESYSTEMCMP_TYPE_REGULAR) {
		errno = EISDIR;
		return (-1);
	}
	if (offset >= object->size)
		return (0);
	available = object->size - (size_t)offset;
	if (length > available)
		length = available;
	memcpy(buffer, object->data + (size_t)offset, length);
	return ((ssize_t)length);
}

ssize_t
scratch_write(struct scratch_store *store, struct filesystemcmp_handle handle,
    uint64_t offset, const void *buffer, size_t length)
{
	struct scratch_object *object;
	uint8_t *data;
	size_t end, capacity;

	if (store == NULL || (buffer == NULL && length != 0) ||
	    offset > SIZE_MAX || length > SIZE_MAX - (size_t)offset) {
		errno = EINVAL;
		return (-1);
	}
	object = resolve(store, handle);
	if (object == NULL)
		return (-1);
	if (object->type != FILESYSTEMCMP_TYPE_REGULAR) {
		errno = EISDIR;
		return (-1);
	}
	end = (size_t)offset + length;
	if (end > store->limits.max_file_bytes ||
	    (end > object->size &&
	    end - object->size > store->limits.max_bytes - store->bytes)) {
		errno = ENOSPC;
		return (-1);
	}
	if (end > object->capacity) {
		capacity = object->capacity == 0 ? 64 : object->capacity;
		while (capacity < end && capacity <= SIZE_MAX / 2)
			capacity *= 2;
		if (capacity < end)
			capacity = end;
		if (capacity > store->limits.max_file_bytes)
			capacity = store->limits.max_file_bytes;
		data = realloc(object->data, capacity);
		if (data == NULL)
			return (-1);
		if (capacity > object->capacity)
			memset(data + object->capacity, 0,
			    capacity - object->capacity);
		object->data = data;
		object->capacity = capacity;
	}
	if (end > object->size) {
		store->bytes += end - object->size;
		object->size = end;
	}
	memcpy(object->data + (size_t)offset, buffer, length);
	object->mtime = now_seconds();
	return ((ssize_t)length);
}

int
scratch_stat(struct scratch_store *store, struct filesystemcmp_handle handle,
    struct filesystemcmp_stat_reply *stat)
{
	struct scratch_object *object;

	if (store == NULL || stat == NULL) {
		errno = EINVAL;
		return (-1);
	}
	object = resolve(store, handle);
	if (object == NULL)
		return (-1);
	memset(stat, 0, sizeof(*stat));
	stat->size = object->size;
	stat->inode = handle.object;
	stat->modified_sec = object->mtime;
	stat->mode = object->mode | (object->type ==
	    FILESYSTEMCMP_TYPE_DIRECTORY ? S_IFDIR : S_IFREG);
	stat->type = object->type;
	return (0);
}

static int
directory_empty(struct scratch_store *store, uint64_t directory)
{
	uint32_t i;

	for (i = 1; i <= store->limits.max_objects; i++)
		if (store->objects[i].live &&
		    store->objects[i].parent == directory)
			return (0);
	return (1);
}

int
scratch_unlink(struct scratch_store *store,
    struct filesystemcmp_handle directory, const void *name, size_t length)
{
	struct scratch_object *dir, *object;

	if (store == NULL || !valid_name(name, length)) {
		errno = EINVAL;
		return (-1);
	}
	dir = resolve(store, directory);
	if (dir == NULL)
		return (-1);
	if (dir->type != FILESYSTEMCMP_TYPE_DIRECTORY) {
		errno = ENOTDIR;
		return (-1);
	}
	object = find_child(store, directory.object, name, length);
	if (object == NULL)
		return (-1);
	if (object->type == FILESYSTEMCMP_TYPE_DIRECTORY &&
	    !directory_empty(store, (uint64_t)(object - store->objects))) {
		errno = ENOTEMPTY;
		return (-1);
	}
	store->bytes -= object->size;
	store->nobjects--;
	free(object->data);
	object->data = NULL;
	object->size = 0;
	object->capacity = 0;
	object->live = false;
	return (0);
}

int
scratch_rename(struct scratch_store *store,
    struct filesystemcmp_handle old_directory, const void *old_name,
    size_t old_length, struct filesystemcmp_handle new_directory,
    const void *new_name, size_t new_length)
{
	struct scratch_object *old_dir, *new_dir, *object;

	if (store == NULL || !valid_name(old_name, old_length) ||
	    !valid_name(new_name, new_length)) {
		errno = EINVAL;
		return (-1);
	}
	old_dir = resolve(store, old_directory);
	new_dir = resolve(store, new_directory);
	if (old_dir == NULL || new_dir == NULL)
		return (-1);
	if (old_dir->type != FILESYSTEMCMP_TYPE_DIRECTORY ||
	    new_dir->type != FILESYSTEMCMP_TYPE_DIRECTORY) {
		errno = ENOTDIR;
		return (-1);
	}
	object = find_child(store, old_directory.object, old_name, old_length);
	if (object == NULL)
		return (-1);
	if (object->type == FILESYSTEMCMP_TYPE_DIRECTORY &&
	    new_directory.object == (uint64_t)(object - store->objects)) {
		errno = EINVAL;
		return (-1);
	}
	if (find_child(store, new_directory.object, new_name, new_length) !=
	    NULL) {
		errno = EEXIST;
		return (-1);
	}
	if (errno != ENOENT)
		return (-1);
	object->parent = new_directory.object;
	object->name_length = (uint16_t)new_length;
	memcpy(object->name, new_name, new_length);
	object->name[new_length] = '\0';
	object->mtime = now_seconds();
	return (0);
}

uint64_t
scratch_bytes(const struct scratch_store *store)
{

	return (store->bytes);
}

uint32_t
scratch_objects(const struct scratch_store *store)
{

	return (store->nobjects);
}
