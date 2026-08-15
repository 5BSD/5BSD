/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/endian.h>
#include <sys/mount.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "virtiofsd_export.h"

struct virtiofsd_node {
	int fd;
	char *path;
	dev_t dev;
	ino_t ino;
	uint32_t generation;
	uint64_t lookups;
	bool allocated;
};

#define	VIRTIOFSD_EXPORT_STATE_MAGIC	UINT32_C(0x54505845) /* "EXPT" */
#define	VIRTIOFSD_EXPORT_STATE_VERSION	1U
#define	VIRTIOFSD_EXPORT_STATE_HEADER	16U
#define	VIRTIOFSD_EXPORT_STATE_NODE	40U

struct virtiofsd_export_restore {
	struct virtiofsd_node *nodes;
	size_t capacity;
	int rootfd;
};

struct virtiofsd_export {
	pthread_mutex_t mutex;
	struct virtiofsd_node *nodes;
	size_t capacity;
	int rootfd;
};

static bool
virtiofsd_export_type_allowed(mode_t mode)
{

	/*
	 * The read-only daemon exports filesystem data, not host device
	 * authority or IPC endpoints.  Special files would also require a
	 * Linux dev_t translation rather than copying the host st_rdev.
	 */
	return (S_ISREG(mode) || S_ISDIR(mode) || S_ISLNK(mode));
}

static int
virtiofsd_export_node_locked(struct virtiofsd_export *export,
    uint64_t nodeid, struct virtiofsd_node **node)
{
	uint32_t generation, slot_value;
	size_t slot;

	if (nodeid == VIRTIOFSD_ROOT_NODEID) {
		*node = &export->nodes[0];
		return (0);
	}
	slot_value = (uint32_t)nodeid;
	generation = (uint32_t)(nodeid >> 32);
	if (slot_value < 2 || generation == 0)
		return (ESTALE);
	slot = (size_t)slot_value - 1;
	if (slot >= export->capacity || !export->nodes[slot].allocated ||
	    export->nodes[slot].generation != generation)
		return (ESTALE);
	*node = &export->nodes[slot];
	return (0);
}

static uint64_t
virtiofsd_export_nodeid(size_t slot, uint32_t generation)
{

	return ((uint64_t)generation << 32 | (uint32_t)(slot + 1));
}

int
virtiofsd_export_component_valid(const void *name, size_t length)
{
	const uint8_t *bytes;

	if (name == NULL || length == 0 || length > VIRTIOFSD_NAME_MAX)
		return (EINVAL);
	bytes = name;
	if ((length == 1 && bytes[0] == '.') ||
	    (length == 2 && bytes[0] == '.' && bytes[1] == '.'))
		return (EINVAL);
	if (memchr(bytes, '/', length) != NULL ||
	    memchr(bytes, '\0', length) != NULL)
		return (EINVAL);
	return (0);
}

int
virtiofsd_export_create(int rootfd, size_t capacity,
    struct virtiofsd_export **result)
{
	struct virtiofsd_export *export;
	struct stat sb;
	int fd, error;

	if (rootfd < 0 || result == NULL || capacity < 2 ||
	    capacity > UINT32_MAX - 1)
		return (EINVAL);
	*result = NULL;
	fd = fcntl(rootfd, F_DUPFD_CLOEXEC, 0);
	if (fd == -1)
		return (errno);
	if (fstat(fd, &sb) == -1) {
		error = errno;
		close(fd);
		return (error);
	}
	if (!S_ISDIR(sb.st_mode)) {
		close(fd);
		return (ENOTDIR);
	}
	export = calloc(1, sizeof(*export));
	if (export == NULL) {
		close(fd);
		return (ENOMEM);
	}
	export->nodes = calloc(capacity, sizeof(*export->nodes));
	if (export->nodes == NULL) {
		close(fd);
		free(export);
		return (ENOMEM);
	}
	error = pthread_mutex_init(&export->mutex, NULL);
	if (error != 0) {
		close(fd);
		free(export->nodes);
		free(export);
		return (error);
	}
	export->capacity = capacity;
	export->rootfd = fd;
	export->nodes[0] = (struct virtiofsd_node) {
		.fd = fd,
		.path = strdup(""),
		.dev = sb.st_dev,
		.ino = sb.st_ino,
		.generation = 1,
		.lookups = UINT64_MAX,
		.allocated = true,
	};
	if (export->nodes[0].path == NULL) {
		pthread_mutex_destroy(&export->mutex);
		close(fd);
		free(export->nodes);
		free(export);
		return (ENOMEM);
	}
	*result = export;
	return (0);
}

void
virtiofsd_export_reset(struct virtiofsd_export *export)
{
	size_t i;

	if (export == NULL)
		return;
	pthread_mutex_lock(&export->mutex);
	for (i = 1; i < export->capacity; i++) {
		if (export->nodes[i].allocated) {
			close(export->nodes[i].fd);
			free(export->nodes[i].path);
			export->nodes[i].fd = -1;
			export->nodes[i].path = NULL;
			export->nodes[i].dev = 0;
			export->nodes[i].ino = 0;
			export->nodes[i].lookups = 0;
			export->nodes[i].allocated = false;
		}
	}
	pthread_mutex_unlock(&export->mutex);
}

void
virtiofsd_export_destroy(struct virtiofsd_export *export)
{

	if (export == NULL)
		return;
	virtiofsd_export_reset(export);
	free(export->nodes[0].path);
	close(export->rootfd);
	pthread_mutex_destroy(&export->mutex);
	free(export->nodes);
	free(export);
}

static void
virtiofsd_export_nodes_destroy(struct virtiofsd_node *nodes, size_t capacity,
    bool root_owned)
{
	size_t i, first;

	if (nodes == NULL)
		return;
	first = root_owned ? 0 : 1;
	for (i = first; i < capacity; i++) {
		if (nodes[i].allocated && nodes[i].fd >= 0)
			(void)close(nodes[i].fd);
		free(nodes[i].path);
	}
	free(nodes);
}

int
virtiofsd_export_state_size(struct virtiofsd_export *export, size_t *result)
{
	size_t i, size, path_len;

	if (export == NULL || result == NULL)
		return (EINVAL);
	size = VIRTIOFSD_EXPORT_STATE_HEADER;
	pthread_mutex_lock(&export->mutex);
	for (i = 1; i < export->capacity; i++) {
		if (!export->nodes[i].allocated)
			continue;
		if (export->nodes[i].path == NULL) {
			pthread_mutex_unlock(&export->mutex);
			return (EPROTO);
		}
		path_len = strlen(export->nodes[i].path);
		if (path_len == 0 || path_len > PATH_MAX ||
		    size > SIZE_MAX - VIRTIOFSD_EXPORT_STATE_NODE - path_len) {
			pthread_mutex_unlock(&export->mutex);
			return (EOVERFLOW);
		}
		size += VIRTIOFSD_EXPORT_STATE_NODE + path_len;
	}
	pthread_mutex_unlock(&export->mutex);
	*result = size;
	return (0);
}

int
virtiofsd_export_state_write(struct virtiofsd_export *export, void *buffer,
    size_t capacity, size_t *written)
{
	struct stat sb;
	uint8_t *bytes;
	size_t count, i, offset, path_len;
	uint32_t type;

	if (export == NULL || buffer == NULL || written == NULL)
		return (EINVAL);
	bytes = buffer;
	offset = VIRTIOFSD_EXPORT_STATE_HEADER;
	count = 0;
	pthread_mutex_lock(&export->mutex);
	for (i = 1; i < export->capacity; i++) {
		if (!export->nodes[i].allocated)
			continue;
		path_len = export->nodes[i].path == NULL ? 0 :
		    strlen(export->nodes[i].path);
		if (path_len == 0 || path_len > PATH_MAX ||
		    offset > capacity ||
		    VIRTIOFSD_EXPORT_STATE_NODE > capacity - offset ||
		    path_len > capacity - offset - VIRTIOFSD_EXPORT_STATE_NODE) {
			pthread_mutex_unlock(&export->mutex);
			return (path_len == 0 ? EPROTO : ENOBUFS);
		}
		if (fstat(export->nodes[i].fd, &sb) != 0) {
			int error = errno;

			pthread_mutex_unlock(&export->mutex);
			return (error);
		}
		type = S_ISREG(sb.st_mode) ? 1U : S_ISDIR(sb.st_mode) ? 2U :
		    S_ISLNK(sb.st_mode) ? 3U : 0U;
		if (type == 0) {
			pthread_mutex_unlock(&export->mutex);
			return (EPROTO);
		}
		le64enc(bytes + offset, virtiofsd_export_nodeid(i,
		    export->nodes[i].generation));
		le64enc(bytes + offset + 8, export->nodes[i].lookups);
		le64enc(bytes + offset + 16,
		    S_ISREG(sb.st_mode) ? (uint64_t)sb.st_size : 0);
		le32enc(bytes + offset + 24, type);
		le32enc(bytes + offset + 28, (uint32_t)path_len);
		le64enc(bytes + offset + 32, 0);
		memcpy(bytes + offset + VIRTIOFSD_EXPORT_STATE_NODE,
		    export->nodes[i].path, path_len);
		offset += VIRTIOFSD_EXPORT_STATE_NODE + path_len;
		count++;
	}
	pthread_mutex_unlock(&export->mutex);
	if (capacity < VIRTIOFSD_EXPORT_STATE_HEADER)
		return (ENOBUFS);
	le32enc(bytes, VIRTIOFSD_EXPORT_STATE_MAGIC);
	le16enc(bytes + 4, VIRTIOFSD_EXPORT_STATE_VERSION);
	le16enc(bytes + 6, 0);
	le32enc(bytes + 8, (uint32_t)count);
	le32enc(bytes + 12, (uint32_t)offset);
	*written = offset;
	return (0);
}

static int
virtiofsd_export_restore_path_valid(const uint8_t *path, size_t length)
{
	size_t start, i;

	if (path == NULL || length == 0 || length > PATH_MAX ||
	    path[0] == '/' || path[length - 1] == '/' ||
	    memchr(path, '\0', length) != NULL)
		return (EINVAL);
	for (start = 0; start < length; start = i + 1) {
		for (i = start; i < length && path[i] != '/'; i++)
			;
		if (virtiofsd_export_component_valid(path + start,
		    i - start) != 0)
			return (EINVAL);
		if (i == length)
			break;
	}
	return (0);
}

int
virtiofsd_export_restore_prepare(struct virtiofsd_export *export,
    const void *buffer, size_t length, struct virtiofsd_export_restore **result)
{
	struct virtiofsd_export_restore *restore;
	struct virtiofsd_node *node;
	const uint8_t *bytes, *path;
	struct stat sb;
	uint64_t nodeid, lookups, file_size;
	size_t count, i, offset, path_len, slot, j;
	uint32_t generation, slot_value, type;
	int fd, error;

	if (export == NULL || buffer == NULL || result == NULL)
		return (EINVAL);
	*result = NULL;
	bytes = buffer;
	if (length < VIRTIOFSD_EXPORT_STATE_HEADER ||
	    le32dec(bytes) != VIRTIOFSD_EXPORT_STATE_MAGIC ||
	    le16dec(bytes + 4) != VIRTIOFSD_EXPORT_STATE_VERSION ||
	    le16dec(bytes + 6) != 0 || le32dec(bytes + 12) != length)
		return (EPROTO);
	count = le32dec(bytes + 8);
	if (count >= export->capacity ||
	    count > (length - VIRTIOFSD_EXPORT_STATE_HEADER) /
	    VIRTIOFSD_EXPORT_STATE_NODE)
		return (ENOSPC);
	restore = calloc(1, sizeof(*restore));
	if (restore == NULL)
		return (ENOMEM);
	restore->rootfd = -1;
	restore->nodes = calloc(export->capacity, sizeof(*restore->nodes));
	if (restore->nodes == NULL) {
		free(restore);
		return (ENOMEM);
	}
	restore->capacity = export->capacity;
	restore->rootfd = fcntl(export->rootfd, F_DUPFD_CLOEXEC, 0);
	if (restore->rootfd == -1) {
		error = errno;
		goto fail;
	}
	offset = VIRTIOFSD_EXPORT_STATE_HEADER;
	for (i = 0; i < count; i++) {
		if (offset > length || VIRTIOFSD_EXPORT_STATE_NODE > length - offset) {
			error = EPROTO;
			goto fail;
		}
		nodeid = le64dec(bytes + offset);
		lookups = le64dec(bytes + offset + 8);
		file_size = le64dec(bytes + offset + 16);
		type = le32dec(bytes + offset + 24);
		path_len = le32dec(bytes + offset + 28);
		if (le64dec(bytes + offset + 32) != 0 || lookups == 0 ||
		    type < 1 || type > 3 || path_len > length - offset -
		    VIRTIOFSD_EXPORT_STATE_NODE ||
		    (type != 1 && file_size != 0)) {
			error = EPROTO;
			goto fail;
		}
		slot_value = (uint32_t)nodeid;
		generation = (uint32_t)(nodeid >> 32);
		if (slot_value < 2 || generation == 0) {
			error = EPROTO;
			goto fail;
		}
		slot = (size_t)slot_value - 1;
		if (slot >= restore->capacity || restore->nodes[slot].allocated) {
			error = EPROTO;
			goto fail;
		}
		path = bytes + offset + VIRTIOFSD_EXPORT_STATE_NODE;
		if (virtiofsd_export_restore_path_valid(path, path_len) != 0) {
			error = EPROTO;
			goto fail;
		}
		node = &restore->nodes[slot];
		node->path = malloc(path_len + 1);
		if (node->path == NULL) {
			error = ENOMEM;
			goto fail;
		}
		memcpy(node->path, path, path_len);
		node->path[path_len] = '\0';
		fd = openat(export->rootfd, node->path,
		    O_PATH | O_NOFOLLOW | O_CLOEXEC | O_RESOLVE_BENEATH);
		if (fd == -1) {
			error = errno;
			goto fail;
		}
		if (fstat(fd, &sb) != 0) {
			error = errno;
			close(fd);
			goto fail;
		}
		if ((type == 1 && (!S_ISREG(sb.st_mode) ||
		    (uint64_t)sb.st_size != file_size)) ||
		    (type == 2 && !S_ISDIR(sb.st_mode)) ||
		    (type == 3 && !S_ISLNK(sb.st_mode))) {
			close(fd);
			error = ESTALE;
			goto fail;
		}
		for (j = 1; j < restore->capacity; j++) {
			if (restore->nodes[j].allocated &&
			    restore->nodes[j].dev == sb.st_dev &&
			    restore->nodes[j].ino == sb.st_ino) {
				close(fd);
				error = EPROTO;
				goto fail;
			}
		}
		node->fd = fd;
		node->dev = sb.st_dev;
		node->ino = sb.st_ino;
		node->generation = generation;
		node->lookups = lookups;
		node->allocated = true;
		offset += VIRTIOFSD_EXPORT_STATE_NODE + path_len;
	}
	if (offset != length) {
		error = EPROTO;
		goto fail;
	}
	*result = restore;
	return (0);
fail:
	virtiofsd_export_restore_destroy(restore);
	return (error);
}

int
virtiofsd_export_restore_open(struct virtiofsd_export_restore *restore,
    uint64_t nodeid, bool directory, int *result)
{
	struct virtiofsd_node *node;
	uint32_t slot_value, generation;
	size_t slot;
	struct stat sb;
	int fd;

	if (restore == NULL || result == NULL)
		return (EINVAL);
	*result = -1;
	if (nodeid == VIRTIOFSD_ROOT_NODEID) {
		fd = openat(restore->rootfd, ".",
		    O_RDONLY | O_CLOEXEC | (directory ? O_DIRECTORY : 0));
		if (fd == -1)
			return (errno);
		if (!directory) {
			(void)close(fd);
			return (EISDIR);
		}
		*result = fd;
		return (0);
	}
	slot_value = (uint32_t)nodeid;
	generation = (uint32_t)(nodeid >> 32);
	if (slot_value < 2 || generation == 0)
		return (ESTALE);
	slot = (size_t)slot_value - 1;
	if (slot >= restore->capacity || !restore->nodes[slot].allocated ||
	    restore->nodes[slot].generation != generation)
		return (ESTALE);
	node = &restore->nodes[slot];
	if (fstat(node->fd, &sb) != 0)
		return (errno);
	if (directory != S_ISDIR(sb.st_mode))
		return (directory ? ENOTDIR : EISDIR);
	fd = openat(node->fd, "", O_RDONLY | O_EMPTY_PATH | O_CLOEXEC |
	    O_NOFOLLOW | (directory ? O_DIRECTORY : 0));
	if (fd == -1)
		return (errno);
	*result = fd;
	return (0);
}

int
virtiofsd_export_restore_open_path(struct virtiofsd_export_restore *restore,
    uint64_t nodeid, const void *path_buffer, size_t path_len, bool directory,
    uint64_t expected_size, int *result)
{
	struct virtiofsd_node *node;
	const uint8_t *path;
	char component[PATH_MAX + 1];
	struct stat sb;
	uint32_t generation, slot_value;
	size_t slot;
	int error, fd;

	if (restore == NULL || result == NULL ||
	    (path_buffer == NULL && path_len != 0))
		return (EINVAL);
	*result = -1;
	path = path_buffer;
	if (path_len == 0) {
		if (!directory || nodeid != VIRTIOFSD_ROOT_NODEID)
			return (EPROTO);
		fd = openat(restore->rootfd, ".",
		    O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	} else {
		slot_value = (uint32_t)nodeid;
		generation = (uint32_t)(nodeid >> 32);
		if (slot_value < 2 || generation == 0)
			return (EPROTO);
		if (virtiofsd_export_restore_path_valid(path, path_len) != 0)
			return (EPROTO);
		slot = (size_t)slot_value - 1;
		if (slot < restore->capacity &&
		    restore->nodes[slot].allocated &&
		    restore->nodes[slot].generation == generation) {
			node = &restore->nodes[slot];
			if (strlen(node->path) != path_len ||
			    memcmp(node->path, path, path_len) != 0)
				return (EPROTO);
			if (fstat(node->fd, &sb) != 0)
				return (errno);
			if (directory != S_ISDIR(sb.st_mode))
				return (EPROTO);
		}
		memcpy(component, path, path_len);
		component[path_len] = '\0';
		fd = openat(restore->rootfd, component,
		    O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_RESOLVE_BENEATH |
		    (directory ? O_DIRECTORY : 0));
	}
	if (fd == -1)
		return (errno);
	if (fstat(fd, &sb) != 0) {
		error = errno;
		(void)close(fd);
		return (error);
	}
	if (directory != S_ISDIR(sb.st_mode) ||
	    (!directory && (!S_ISREG(sb.st_mode) ||
	    (uint64_t)sb.st_size != expected_size))) {
		(void)close(fd);
		return (ESTALE);
	}
	*result = fd;
	return (0);
}

void
virtiofsd_export_restore_commit(struct virtiofsd_export *export,
    struct virtiofsd_export_restore *restore)
{
	struct virtiofsd_node *old;
	size_t old_capacity;

	if (export == NULL || restore == NULL)
		return;
	pthread_mutex_lock(&export->mutex);
	old = export->nodes;
	old_capacity = export->capacity;
	restore->nodes[0] = old[0];
	export->nodes = restore->nodes;
	export->capacity = restore->capacity;
	restore->nodes = NULL;
	pthread_mutex_unlock(&export->mutex);
	/* The root descriptor and path moved to the replacement table. */
	old[0].allocated = false;
	old[0].path = NULL;
	virtiofsd_export_nodes_destroy(old, old_capacity, false);
}

void
virtiofsd_export_restore_destroy(struct virtiofsd_export_restore *restore)
{

	if (restore == NULL)
		return;
	virtiofsd_export_nodes_destroy(restore->nodes, restore->capacity, true);
	if (restore->rootfd >= 0)
		(void)close(restore->rootfd);
	free(restore);
}

size_t
virtiofsd_export_node_count(struct virtiofsd_export *export)
{
	size_t count, i;

	if (export == NULL)
		return (0);
	count = 0;
	pthread_mutex_lock(&export->mutex);
	for (i = 0; i < export->capacity; i++)
		count += export->nodes[i].allocated ? 1 : 0;
	pthread_mutex_unlock(&export->mutex);
	return (count);
}

int
virtiofsd_export_lookup(struct virtiofsd_export *export, uint64_t parent_id,
    const void *name, size_t name_len, uint64_t *nodeid, struct stat *sb)
{
	struct virtiofsd_node *parent;
	char component[VIRTIOFSD_NAME_MAX + 1], path[PATH_MAX + 1];
	struct stat candidate;
	size_t free_slot, i;
	int fd, parentfd, error;

	if (export == NULL || nodeid == NULL || sb == NULL)
		return (EINVAL);
	error = virtiofsd_export_component_valid(name, name_len);
	if (error != 0)
		return (error);
	memcpy(component, name, name_len);
	component[name_len] = '\0';
	pthread_mutex_lock(&export->mutex);
	error = virtiofsd_export_node_locked(export, parent_id, &parent);
	if (error == 0) {
		if (parent->path == NULL ||
		    snprintf(path, sizeof(path), "%s%s%s", parent->path,
		    parent->path[0] == '\0' ? "" : "/", component) >=
		    (int)sizeof(path))
			error = ENAMETOOLONG;
	}
	if (error == 0) {
		parentfd = fcntl(parent->fd, F_DUPFD_CLOEXEC, 0);
		if (parentfd == -1)
			error = errno;
	}
	pthread_mutex_unlock(&export->mutex);
	if (error != 0)
		return (error);
	if (fstat(parentfd, &candidate) == -1) {
		error = errno;
		close(parentfd);
		return (error);
	}
	if (!S_ISDIR(candidate.st_mode)) {
		close(parentfd);
		return (ENOTDIR);
	}
	fd = openat(parentfd, component,
	    O_PATH | O_NOFOLLOW | O_CLOEXEC | O_RESOLVE_BENEATH);
	close(parentfd);
	if (fd == -1) {
		return (errno);
	}
	if (fstat(fd, &candidate) == -1) {
		error = errno;
		close(fd);
		return (error);
	}
	if (!virtiofsd_export_type_allowed(candidate.st_mode)) {
		close(fd);
		return (EOPNOTSUPP);
	}
	pthread_mutex_lock(&export->mutex);
	free_slot = export->capacity;
	for (i = 1; i < export->capacity; i++) {
		if (export->nodes[i].allocated &&
		    export->nodes[i].dev == candidate.st_dev &&
		    export->nodes[i].ino == candidate.st_ino) {
			if (export->nodes[i].lookups == UINT64_MAX) {
				error = EOVERFLOW;
				close(fd);
				goto out;
			}
			export->nodes[i].lookups++;
			*nodeid = virtiofsd_export_nodeid(i,
			    export->nodes[i].generation);
			*sb = candidate;
			close(fd);
			error = 0;
			goto out;
		}
		if (!export->nodes[i].allocated &&
		    free_slot == export->capacity)
			free_slot = i;
	}
	if (free_slot == export->capacity) {
		close(fd);
		error = ENOSPC;
		goto out;
	}
	if (++export->nodes[free_slot].generation == 0)
		export->nodes[free_slot].generation = 1;
	export->nodes[free_slot].fd = fd;
	export->nodes[free_slot].path = strdup(path);
	if (export->nodes[free_slot].path == NULL) {
		close(fd);
		error = ENOMEM;
		goto out;
	}
	export->nodes[free_slot].dev = candidate.st_dev;
	export->nodes[free_slot].ino = candidate.st_ino;
	export->nodes[free_slot].lookups = 1;
	export->nodes[free_slot].allocated = true;
	*nodeid = virtiofsd_export_nodeid(free_slot,
	    export->nodes[free_slot].generation);
	*sb = candidate;
	error = 0;
out:
	pthread_mutex_unlock(&export->mutex);
	return (error);
}

int
virtiofsd_export_forget(struct virtiofsd_export *export, uint64_t nodeid,
    uint64_t count)
{
	struct virtiofsd_node *node;
	int error;

	if (export == NULL || count == 0 ||
	    nodeid == VIRTIOFSD_ROOT_NODEID)
		return (EINVAL);
	pthread_mutex_lock(&export->mutex);
	error = virtiofsd_export_node_locked(export, nodeid, &node);
	if (error == 0) {
		if (count > node->lookups) {
			error = EINVAL;
		} else {
			node->lookups -= count;
			if (node->lookups == 0) {
				close(node->fd);
				free(node->path);
				node->fd = -1;
				node->path = NULL;
				node->allocated = false;
				node->dev = 0;
				node->ino = 0;
			}
		}
	}
	pthread_mutex_unlock(&export->mutex);
	return (error);
}

int
virtiofsd_export_stat(struct virtiofsd_export *export, uint64_t nodeid,
    struct stat *sb)
{
	struct virtiofsd_node *node;
	int fd, error;

	if (export == NULL || sb == NULL)
		return (EINVAL);
	pthread_mutex_lock(&export->mutex);
	error = virtiofsd_export_node_locked(export, nodeid, &node);
	if (error == 0) {
		fd = fcntl(node->fd, F_DUPFD_CLOEXEC, 0);
		if (fd == -1)
			error = errno;
	}
	pthread_mutex_unlock(&export->mutex);
	if (error == 0) {
		if (fstat(fd, sb) == -1)
			error = errno;
		close(fd);
	}
	return (error);
}

int
virtiofsd_export_open(struct virtiofsd_export *export, uint64_t nodeid,
    int flags, int *result)
{
	struct virtiofsd_node *node;
	int fd, pathfd, error;

	if (export == NULL || result == NULL ||
	    (flags & (O_CREAT | O_EXCL | O_NOFOLLOW | O_RESOLVE_BENEATH |
	    O_EMPTY_PATH | O_PATH)) != 0)
		return (EINVAL);
	/*
	 * This export is deliberately read-only.  Keep that authority boundary
	 * in the object which owns the export descriptor, rather than relying on
	 * every FUSE opcode dispatcher to sanitize open flags correctly.
	 */
	if ((flags & O_ACCMODE) != O_RDONLY ||
	    (flags & (O_APPEND | O_TRUNC)) != 0)
		return (EROFS);
	*result = -1;
	pthread_mutex_lock(&export->mutex);
	error = virtiofsd_export_node_locked(export, nodeid, &node);
	if (error == 0) {
		pathfd = fcntl(node->fd, F_DUPFD_CLOEXEC, 0);
		if (pathfd == -1)
			error = errno;
	}
	pthread_mutex_unlock(&export->mutex);
	if (error == 0) {
		/*
		 * The stored O_PATH descriptor may name a symlink.  Reopening
		 * it must never follow that link, or an export-visible symlink
		 * could become an authority escape at OPEN time.
		 */
		fd = openat(pathfd, "", flags | O_EMPTY_PATH | O_CLOEXEC |
		    O_NOFOLLOW);
		if (fd == -1)
			error = errno;
		else
			*result = fd;
		close(pathfd);
	}
	return (error);
}

int
virtiofsd_export_path(struct virtiofsd_export *export, uint64_t nodeid,
    void *buffer, size_t capacity, size_t *length)
{
	struct virtiofsd_node *node;
	size_t path_len;
	int error;

	if (export == NULL || buffer == NULL || length == NULL)
		return (EINVAL);
	*length = 0;
	pthread_mutex_lock(&export->mutex);
	error = virtiofsd_export_node_locked(export, nodeid, &node);
	if (error == 0) {
		if (node->path == NULL)
			error = EPROTO;
		else {
			path_len = strlen(node->path);
			if (path_len > capacity)
				error = ENOBUFS;
			else {
				memcpy(buffer, node->path, path_len);
				*length = path_len;
			}
		}
	}
	pthread_mutex_unlock(&export->mutex);
	return (error);
}

int
virtiofsd_export_readlink(struct virtiofsd_export *export, uint64_t nodeid,
    void *buffer, size_t capacity, size_t *length)
{
	struct virtiofsd_node *node;
	struct stat sb;
	ssize_t amount;
	int pathfd, error;

	if (export == NULL || buffer == NULL || capacity == 0 ||
	    length == NULL)
		return (EINVAL);
	*length = 0;
	pthread_mutex_lock(&export->mutex);
	error = virtiofsd_export_node_locked(export, nodeid, &node);
	if (error == 0) {
		pathfd = fcntl(node->fd, F_DUPFD_CLOEXEC, 0);
		if (pathfd == -1)
			error = errno;
	}
	pthread_mutex_unlock(&export->mutex);
	if (error != 0)
		return (error);
	if (fstat(pathfd, &sb) == -1)
		error = errno;
	else if (!S_ISLNK(sb.st_mode))
		error = EINVAL;
	if (error == 0) {
		do {
			amount = readlinkat(pathfd, "", buffer, capacity);
		} while (amount < 0 && errno == EINTR);
		if (amount < 0)
			error = errno;
		else if ((size_t)amount == capacity)
			error = EOVERFLOW;
		else
			*length = (size_t)amount;
	}
	(void)close(pathfd);
	return (error);
}

int
virtiofsd_export_statfs(struct virtiofsd_export *export, uint64_t nodeid,
    struct statfs *sb)
{
	struct virtiofsd_node *node;
	int fd, error;

	if (export == NULL || sb == NULL)
		return (EINVAL);
	pthread_mutex_lock(&export->mutex);
	error = virtiofsd_export_node_locked(export, nodeid, &node);
	if (error == 0) {
		fd = fcntl(node->fd, F_DUPFD_CLOEXEC, 0);
		if (fd == -1)
			error = errno;
	}
	pthread_mutex_unlock(&export->mutex);
	if (error == 0) {
		if (fstatfs(fd, sb) == -1)
			error = errno;
		(void)close(fd);
	}
	return (error);
}
