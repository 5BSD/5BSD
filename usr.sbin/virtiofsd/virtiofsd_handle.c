/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/endian.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "virtiofsd_handle.h"

#define	VIRTIOFSD_HANDLE_STATE_MAGIC	UINT32_C(0x4c444e48) /* "HNDL" */
#define	VIRTIOFSD_HANDLE_STATE_VERSION	1U
#define	VIRTIOFSD_HANDLE_STATE_HEADER	16U
#define	VIRTIOFSD_HANDLE_STATE_ENTRY	40U

struct virtiofsd_handle {
	int fd;
	char *path;
	size_t path_len;
	uint64_t file_size;
	uint64_t nodeid;
	uint32_t generation;
	bool directory;
	bool allocated;
};

struct virtiofsd_handles {
	pthread_mutex_t mutex;
	struct virtiofsd_handle *entries;
	size_t capacity;
	size_t count;
};

struct virtiofsd_handles_restore {
	struct virtiofsd_handle *entries;
	size_t capacity;
	size_t count;
};

static int
handle_path_valid(const uint8_t *path, size_t length, bool directory)
{
	size_t component, i;

	if (length == 0)
		return (directory ? 0 : EINVAL);
	if (path == NULL || length > PATH_MAX || path[0] == '/' ||
	    path[length - 1] == '/' || memchr(path, '\0', length) != NULL)
		return (EINVAL);
	for (component = 0; component < length; component = i + 1) {
		for (i = component; i < length && path[i] != '/'; i++)
			;
		if (i == component ||
		    (i - component == 1 && path[component] == '.') ||
		    (i - component == 2 && path[component] == '.' &&
		    path[component + 1] == '.'))
			return (EINVAL);
		if (i == length)
			break;
	}
	return (0);
}

static uint64_t
handle_id(size_t slot, uint32_t generation)
{

	return ((uint64_t)generation << 32 | (uint32_t)(slot + 1));
}

static int
handle_find_locked(struct virtiofsd_handles *handles, uint64_t id,
    bool directory, struct virtiofsd_handle **result)
{
	uint32_t generation, slot_value;
	size_t slot;

	slot_value = (uint32_t)id;
	generation = (uint32_t)(id >> 32);
	if (slot_value == 0 || generation == 0)
		return (ESTALE);
	slot = (size_t)slot_value - 1;
	if (slot >= handles->capacity || !handles->entries[slot].allocated ||
	    handles->entries[slot].generation != generation ||
	    handles->entries[slot].directory != directory)
		return (ESTALE);
	*result = &handles->entries[slot];
	return (0);
}

int
virtiofsd_handles_create(size_t capacity, struct virtiofsd_handles **result)
{
	struct virtiofsd_handles *handles;
	int error;

	if (capacity == 0 || capacity > UINT32_MAX || result == NULL)
		return (EINVAL);
	*result = NULL;
	handles = calloc(1, sizeof(*handles));
	if (handles == NULL)
		return (ENOMEM);
	handles->entries = calloc(capacity, sizeof(*handles->entries));
	if (handles->entries == NULL) {
		free(handles);
		return (ENOMEM);
	}
	error = pthread_mutex_init(&handles->mutex, NULL);
	if (error != 0) {
		free(handles->entries);
		free(handles);
		return (error);
	}
	handles->capacity = capacity;
	*result = handles;
	return (0);
}

void
virtiofsd_handles_destroy(struct virtiofsd_handles *handles)
{
	size_t i;

	if (handles == NULL)
		return;
	for (i = 0; i < handles->capacity; i++)
		if (handles->entries[i].allocated) {
			(void)close(handles->entries[i].fd);
			free(handles->entries[i].path);
		}
	(void)pthread_mutex_destroy(&handles->mutex);
	free(handles->entries);
	free(handles);
}

int
virtiofsd_handles_insert(struct virtiofsd_handles *handles, int fd,
    uint64_t nodeid, bool directory, uint64_t *id)
{
	struct virtiofsd_handle *entry;
	size_t i;
	int owned_fd;

	if (handles == NULL || fd < 0 || nodeid == 0 || id == NULL)
		return (EINVAL);
	*id = 0;
	owned_fd = fcntl(fd, F_DUPFD_CLOEXEC, 0);
	if (owned_fd == -1)
		return (errno);
	pthread_mutex_lock(&handles->mutex);
	for (i = 0; i < handles->capacity; i++)
		if (!handles->entries[i].allocated)
			break;
	if (i == handles->capacity) {
		pthread_mutex_unlock(&handles->mutex);
		(void)close(owned_fd);
		return (ENOSPC);
	}
	entry = &handles->entries[i];
	if (++entry->generation == 0)
		entry->generation = 1;
	entry->fd = owned_fd;
	entry->nodeid = nodeid;
	entry->directory = directory;
	entry->allocated = true;
	handles->count++;
	*id = handle_id(i, entry->generation);
	pthread_mutex_unlock(&handles->mutex);
	return (0);
}

int
virtiofsd_handles_insert_identity(struct virtiofsd_handles *handles, int fd,
    uint64_t nodeid, bool directory, const void *path, size_t path_len,
    uint64_t *id)
{
	struct virtiofsd_handle *entry;
	struct stat sb;
	char *owned_path;
	size_t i;
	int owned_fd;

	if (handles == NULL || fd < 0 || nodeid == 0 || id == NULL ||
	    (path == NULL && path_len != 0) ||
	    handle_path_valid(path, path_len, directory) != 0)
		return (EINVAL);
	if (fstat(fd, &sb) != 0)
		return (errno);
	if (directory != S_ISDIR(sb.st_mode) ||
	    (!directory && (!S_ISREG(sb.st_mode) || sb.st_size < 0)))
		return (EINVAL);
	*id = 0;
	owned_path = NULL;
	if (path != NULL || path_len != 0) {
		owned_path = malloc(path_len + 1);
		if (owned_path == NULL)
			return (ENOMEM);
		memcpy(owned_path, path, path_len);
		owned_path[path_len] = '\0';
	}
	owned_fd = fcntl(fd, F_DUPFD_CLOEXEC, 0);
	if (owned_fd == -1) {
		free(owned_path);
		return (errno);
	}
	pthread_mutex_lock(&handles->mutex);
	for (i = 0; i < handles->capacity; i++)
		if (!handles->entries[i].allocated)
			break;
	if (i == handles->capacity) {
		pthread_mutex_unlock(&handles->mutex);
		(void)close(owned_fd);
		free(owned_path);
		return (ENOSPC);
	}
	entry = &handles->entries[i];
	if (++entry->generation == 0)
		entry->generation = 1;
	entry->fd = owned_fd;
	entry->path = owned_path;
	entry->path_len = path_len;
	entry->file_size = directory ? 0 : (uint64_t)sb.st_size;
	entry->nodeid = nodeid;
	entry->directory = directory;
	entry->allocated = true;
	handles->count++;
	*id = handle_id(i, entry->generation);
	pthread_mutex_unlock(&handles->mutex);
	return (0);
}

int
virtiofsd_handles_dup(struct virtiofsd_handles *handles, uint64_t id,
    bool directory, int *fd, uint64_t *nodeid)
{
	struct virtiofsd_handle *entry;
	int error, duplicate;

	if (handles == NULL || fd == NULL)
		return (EINVAL);
	*fd = -1;
	pthread_mutex_lock(&handles->mutex);
	error = handle_find_locked(handles, id, directory, &entry);
	if (error == 0) {
		/*
		 * fcntl() duplicates share a directory cursor.  Each FUSE
		 * READDIR request carries its own logical offset, so reopen "."
		 * beneath the held directory to obtain an independent cursor.
		 * This also remains valid after the node lookup is forgotten.
		 */
		if (directory)
			duplicate = openat(entry->fd, ".",
			    O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		else
			duplicate = fcntl(entry->fd, F_DUPFD_CLOEXEC, 0);
		if (duplicate == -1)
			error = errno;
		else {
			*fd = duplicate;
			if (nodeid != NULL)
				*nodeid = entry->nodeid;
		}
	}
	pthread_mutex_unlock(&handles->mutex);
	return (error);
}

int
virtiofsd_handles_remove(struct virtiofsd_handles *handles, uint64_t id,
    bool directory)
{
	struct virtiofsd_handle *entry;
	int error;

	if (handles == NULL)
		return (EINVAL);
	pthread_mutex_lock(&handles->mutex);
	error = handle_find_locked(handles, id, directory, &entry);
	if (error == 0) {
		(void)close(entry->fd);
		free(entry->path);
		entry->fd = -1;
		entry->path = NULL;
		entry->path_len = 0;
		entry->file_size = 0;
		entry->nodeid = 0;
		entry->directory = false;
		entry->allocated = false;
		handles->count--;
	}
	pthread_mutex_unlock(&handles->mutex);
	return (error);
}

int
virtiofsd_handles_remove_node(struct virtiofsd_handles *handles, uint64_t id,
    bool directory, uint64_t nodeid)
{
	struct virtiofsd_handle *entry;
	int error;

	if (handles == NULL || nodeid == 0)
		return (EINVAL);
	pthread_mutex_lock(&handles->mutex);
	error = handle_find_locked(handles, id, directory, &entry);
	if (error == 0 && entry->nodeid != nodeid)
		error = ESTALE;
	if (error == 0) {
		(void)close(entry->fd);
		free(entry->path);
		entry->fd = -1;
		entry->path = NULL;
		entry->path_len = 0;
		entry->file_size = 0;
		entry->nodeid = 0;
		entry->directory = false;
		entry->allocated = false;
		handles->count--;
	}
	pthread_mutex_unlock(&handles->mutex);
	return (error);
}

size_t
virtiofsd_handles_count(struct virtiofsd_handles *handles)
{
	size_t count;

	if (handles == NULL)
		return (0);
	pthread_mutex_lock(&handles->mutex);
	count = handles->count;
	pthread_mutex_unlock(&handles->mutex);
	return (count);
}

int
virtiofsd_handles_state_size(struct virtiofsd_handles *handles,
    size_t *result)
{
	size_t i, size;

	if (handles == NULL || result == NULL)
		return (EINVAL);
	size = VIRTIOFSD_HANDLE_STATE_HEADER;
	pthread_mutex_lock(&handles->mutex);
	for (i = 0; i < handles->capacity; i++) {
		if (!handles->entries[i].allocated)
			continue;
		if (handles->entries[i].path == NULL ||
		    handles->entries[i].path_len > PATH_MAX) {
			pthread_mutex_unlock(&handles->mutex);
			return (EPROTO);
		}
		if (size > SIZE_MAX - VIRTIOFSD_HANDLE_STATE_ENTRY -
		    handles->entries[i].path_len) {
			pthread_mutex_unlock(&handles->mutex);
			return (EOVERFLOW);
		}
		size += VIRTIOFSD_HANDLE_STATE_ENTRY +
		    handles->entries[i].path_len;
	}
	*result = size;
	pthread_mutex_unlock(&handles->mutex);
	return (0);
}

int
virtiofsd_handles_state_write(struct virtiofsd_handles *handles,
    void *buffer, size_t capacity, size_t *written)
{
	uint8_t *bytes;
	size_t count, i, offset;

	if (handles == NULL || buffer == NULL || written == NULL)
		return (EINVAL);
	bytes = buffer;
	offset = VIRTIOFSD_HANDLE_STATE_HEADER;
	count = 0;
	pthread_mutex_lock(&handles->mutex);
	for (i = 0; i < handles->capacity; i++) {
		if (!handles->entries[i].allocated)
			continue;
		if (handles->entries[i].path == NULL ||
		    handles->entries[i].path_len > PATH_MAX) {
			pthread_mutex_unlock(&handles->mutex);
			return (EPROTO);
		}
		if (offset > capacity ||
		    VIRTIOFSD_HANDLE_STATE_ENTRY > capacity - offset ||
		    handles->entries[i].path_len > capacity - offset -
		    VIRTIOFSD_HANDLE_STATE_ENTRY) {
			pthread_mutex_unlock(&handles->mutex);
			return (ENOBUFS);
		}
		le64enc(bytes + offset, handle_id(i,
		    handles->entries[i].generation));
		le64enc(bytes + offset + 8, handles->entries[i].nodeid);
		le64enc(bytes + offset + 16, handles->entries[i].file_size);
		le32enc(bytes + offset + 24,
		    handles->entries[i].directory ? 1U : 0U);
		le32enc(bytes + offset + 28,
		    (uint32_t)handles->entries[i].path_len);
		le64enc(bytes + offset + 32, 0);
		memcpy(bytes + offset + VIRTIOFSD_HANDLE_STATE_ENTRY,
		    handles->entries[i].path, handles->entries[i].path_len);
		offset += VIRTIOFSD_HANDLE_STATE_ENTRY +
		    handles->entries[i].path_len;
		count++;
	}
	pthread_mutex_unlock(&handles->mutex);
	if (capacity < VIRTIOFSD_HANDLE_STATE_HEADER)
		return (ENOBUFS);
	le32enc(bytes, VIRTIOFSD_HANDLE_STATE_MAGIC);
	le16enc(bytes + 4, VIRTIOFSD_HANDLE_STATE_VERSION);
	le16enc(bytes + 6, 0);
	le32enc(bytes + 8, (uint32_t)count);
	le32enc(bytes + 12, (uint32_t)offset);
	*written = offset;
	return (0);
}

int
virtiofsd_handles_restore_prepare(struct virtiofsd_handles *handles,
    virtiofsd_handle_reopen_cb reopen, void *reopen_arg,
    const void *buffer, size_t length,
    struct virtiofsd_handles_restore **result)
{
	struct virtiofsd_handles_restore *restore;
	const uint8_t *bytes;
	uint64_t file_size, id, nodeid;
	uint32_t flags, generation, slot_value;
	size_t count, i, offset, path_len, slot;
	char *path;
	int error, fd;

	if (handles == NULL || reopen == NULL || buffer == NULL ||
	    result == NULL)
		return (EINVAL);
	*result = NULL;
	bytes = buffer;
	if (length < VIRTIOFSD_HANDLE_STATE_HEADER ||
	    le32dec(bytes) != VIRTIOFSD_HANDLE_STATE_MAGIC ||
	    le16dec(bytes + 4) != VIRTIOFSD_HANDLE_STATE_VERSION ||
	    le16dec(bytes + 6) != 0 || le32dec(bytes + 12) != length)
		return (EPROTO);
	count = le32dec(bytes + 8);
	if (count > handles->capacity)
		return (EPROTO);
	restore = calloc(1, sizeof(*restore));
	if (restore == NULL)
		return (ENOMEM);
	restore->entries = calloc(handles->capacity,
	    sizeof(*restore->entries));
	if (restore->entries == NULL) {
		free(restore);
		return (ENOMEM);
	}
	restore->capacity = handles->capacity;
	offset = VIRTIOFSD_HANDLE_STATE_HEADER;
	for (i = 0; i < count; i++) {
		if (offset > length ||
		    VIRTIOFSD_HANDLE_STATE_ENTRY > length - offset) {
			error = EPROTO;
			goto fail;
		}
		id = le64dec(bytes + offset);
		nodeid = le64dec(bytes + offset + 8);
		file_size = le64dec(bytes + offset + 16);
		flags = le32dec(bytes + offset + 24);
		path_len = le32dec(bytes + offset + 28);
		slot_value = (uint32_t)id;
		generation = (uint32_t)(id >> 32);
		if (slot_value == 0 || generation == 0 || flags > 1 ||
		    le64dec(bytes + offset + 32) != 0 || path_len > PATH_MAX ||
		    path_len > length - offset - VIRTIOFSD_HANDLE_STATE_ENTRY ||
		    (flags != 0 && file_size != 0) || nodeid == 0) {
			error = EPROTO;
			goto fail;
		}
		slot = (size_t)slot_value - 1;
		if (slot >= restore->capacity ||
		    restore->entries[slot].allocated) {
			error = EPROTO;
			goto fail;
		}
		if (handle_path_valid(bytes + offset +
		    VIRTIOFSD_HANDLE_STATE_ENTRY, path_len, flags != 0) != 0) {
			error = EPROTO;
			goto fail;
		}
		path = malloc(path_len + 1);
		if (path == NULL) {
			error = ENOMEM;
			goto fail;
		}
		memcpy(path, bytes + offset + VIRTIOFSD_HANDLE_STATE_ENTRY,
		    path_len);
		path[path_len] = '\0';
		error = reopen(reopen_arg, nodeid, path,
		    path_len, flags != 0, file_size, &fd);
		if (error != 0)
			free(path);
		if (error != 0)
			goto fail;
		restore->entries[slot] = (struct virtiofsd_handle) {
			.fd = fd,
			.path = path,
			.path_len = path_len,
			.file_size = file_size,
			.nodeid = nodeid,
			.generation = generation,
			.directory = flags != 0,
			.allocated = true,
		};
		restore->count++;
		offset += VIRTIOFSD_HANDLE_STATE_ENTRY + path_len;
	}
	if (offset != length) {
		error = EPROTO;
		goto fail;
	}
	*result = restore;
	return (0);
fail:
	virtiofsd_handles_restore_destroy(restore);
	return (error);
}

void
virtiofsd_handles_restore_commit(struct virtiofsd_handles *handles,
    struct virtiofsd_handles_restore *restore)
{
	struct virtiofsd_handle *old;
	size_t old_capacity, i;

	if (handles == NULL || restore == NULL)
		return;
	pthread_mutex_lock(&handles->mutex);
	old = handles->entries;
	old_capacity = handles->capacity;
	handles->entries = restore->entries;
	handles->capacity = restore->capacity;
	handles->count = restore->count;
	restore->entries = NULL;
	pthread_mutex_unlock(&handles->mutex);
	for (i = 0; i < old_capacity; i++)
		if (old[i].allocated) {
			(void)close(old[i].fd);
			free(old[i].path);
		}
	free(old);
}

void
virtiofsd_handles_restore_destroy(struct virtiofsd_handles_restore *restore)
{
	size_t i;

	if (restore == NULL)
		return;
	if (restore->entries != NULL)
		for (i = 0; i < restore->capacity; i++)
			if (restore->entries[i].allocated) {
				(void)close(restore->entries[i].fd);
				free(restore->entries[i].path);
			}
	free(restore->entries);
	free(restore);
}
