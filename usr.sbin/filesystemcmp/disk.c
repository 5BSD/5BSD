/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/stat.h>

#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "disk.h"

struct disk_object {
	int		fd;
	uint64_t	generation;
	uint32_t	type;
};

struct disk_store {
	struct disk_object	*objects;
	uint32_t		limit;
	uint32_t		max_file_bytes;
	uint64_t		max_bytes;
	uint64_t		bytes;
	uint64_t		nobjects;
	bool			readonly;
};

static int
scan_directory(int fd, uint64_t maximum_bytes, uint64_t maximum_objects,
    uint64_t *total_bytes, uint64_t *total_objects)
{
	struct dirent *entry;
	struct stat status;
	DIR *directory;
	int child, scanfd, error;

	scanfd = dup(fd);
	if (scanfd == -1)
		return (-1);
	directory = fdopendir(scanfd);
	if (directory == NULL) {
		close(scanfd);
		return (-1);
	}
	errno = 0;
	while ((entry = readdir(directory)) != NULL) {
		if (strcmp(entry->d_name, ".") == 0 ||
		    strcmp(entry->d_name, "..") == 0)
			continue;
		if (fstatat(fd, entry->d_name, &status,
		    AT_SYMLINK_NOFOLLOW) == -1)
			goto fail;
		if (*total_objects >= maximum_objects) {
			errno = ENOSPC;
			goto fail;
		}
		(*total_objects)++;
		if (S_ISREG(status.st_mode)) {
			if (status.st_size < 0 ||
			    (uint64_t)status.st_size >
			    maximum_bytes - *total_bytes) {
				errno = ENOSPC;
				goto fail;
			}
			*total_bytes += (uint64_t)status.st_size;
		} else if (S_ISDIR(status.st_mode)) {
			child = openat(fd, entry->d_name,
			    O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
			if (child == -1)
				goto fail;
			if (scan_directory(child, maximum_bytes, maximum_objects,
			    total_bytes, total_objects) == -1) {
				error = errno;
				close(child);
				errno = error;
				goto fail;
			}
			close(child);
		} else {
			errno = EFTYPE;
			goto fail;
		}
		errno = 0;
	}
	if (errno != 0)
		goto fail;
	closedir(directory);
	return (0);

fail:
	error = errno;
	closedir(directory);
	errno = error;
	return (-1);
}

static int
valid_name(const void *name, size_t length, char output[static
    FILESYSTEMCMP_NAME_MAX + 1])
{
	const uint8_t *bytes;
	size_t i;

	if (name == NULL || length == 0 || length > FILESYSTEMCMP_NAME_MAX ||
	    (length == 1 && memcmp(name, ".", 1) == 0) ||
	    (length == 2 && memcmp(name, "..", 2) == 0)) {
		errno = EINVAL;
		return (-1);
	}
	bytes = name;
	for (i = 0; i < length; i++) {
		if (bytes[i] == '\0' || bytes[i] == '/') {
			errno = EINVAL;
			return (-1);
		}
	}
	memcpy(output, name, length);
	output[length] = '\0';
	return (0);
}

static struct disk_object *
resolve(struct disk_store *store, struct filesystemcmp_handle handle)
{
	struct disk_object *object;

	if (store == NULL || handle.object == 0 || handle.object > store->limit) {
		errno = ESTALE;
		return (NULL);
	}
	object = &store->objects[handle.object];
	if (object->fd == -1 || object->generation != handle.generation) {
		errno = ESTALE;
		return (NULL);
	}
	return (object);
}

static bool
object_is_open(struct disk_store *store, dev_t device, ino_t inode,
    const struct disk_object *exclude)
{
	struct stat status;
	uint32_t i;

	for (i = 1; i <= store->limit; i++) {
		if (&store->objects[i] == exclude || store->objects[i].fd == -1)
			continue;
		if (fstat(store->objects[i].fd, &status) == 0 &&
		    status.st_dev == device && status.st_ino == inode)
			return (true);
	}
	return (false);
}

static int
allocate(struct disk_store *store, int fd, uint32_t type,
    struct filesystemcmp_handle *handle)
{
	struct disk_object *object;
	uint32_t i;

	for (i = 2; i <= store->limit; i++) {
		object = &store->objects[i];
		if (object->fd != -1)
			continue;
		object->generation++;
		if (object->generation == 0)
			object->generation = 1;
		object->fd = fd;
		object->type = type;
		handle->object = i;
		handle->generation = object->generation;
		return (0);
	}
	errno = EMFILE;
	return (-1);
}

static int
open_child(struct disk_store *store, int directory, const char *name,
    struct stat *status)
{
	int fd;

	fd = openat(directory, name,
	    (store->readonly ? O_RDONLY : O_RDWR) | O_CLOEXEC | O_NOFOLLOW);
	if (fd == -1 && !store->readonly &&
	    (errno == EISDIR || errno == EACCES))
		fd = openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd == -1)
		return (-1);
	if (fstat(fd, status) == -1) {
		int error;

		error = errno;
		close(fd);
		errno = error;
		return (-1);
	}
	if (!S_ISREG(status->st_mode) && !S_ISDIR(status->st_mode)) {
		close(fd);
		errno = EFTYPE;
		return (-1);
	}
	if (!store->readonly && S_ISREG(status->st_mode) &&
	    status->st_nlink != 1) {
		close(fd);
		errno = EMLINK;
		return (-1);
	}
	return (fd);
}

int
disk_store_create(int rootfd, bool readonly, uint64_t max_bytes,
    uint32_t max_objects, uint32_t max_file_bytes, struct disk_store **storep)
{
	struct disk_store *store;
	struct stat status;
	uint32_t i;
	int fd;

	if (rootfd < 0 || storep == NULL || max_objects < 2 ||
	    max_objects > 1048576 || max_bytes == 0 || max_file_bytes == 0 ||
	    max_file_bytes > max_bytes ||
	    fstat(rootfd, &status) == -1)
		return (-1);
	if (!S_ISDIR(status.st_mode)) {
		errno = ENOTDIR;
		return (-1);
	}
	fd = fcntl(rootfd, F_DUPFD_CLOEXEC, 0);
	if (fd == -1)
		return (-1);
	store = calloc(1, sizeof(*store));
	if (store == NULL) {
		close(fd);
		return (-1);
	}
	store->objects = calloc((size_t)max_objects + 1,
	    sizeof(*store->objects));
	if (store->objects == NULL) {
		close(fd);
		free(store);
		return (-1);
	}
	for (i = 0; i <= max_objects; i++)
		store->objects[i].fd = -1;
	store->limit = max_objects;
	store->max_file_bytes = max_file_bytes;
	store->max_bytes = max_bytes;
	store->readonly = readonly;
	store->nobjects = 1;	/* The durable root counts as an object. */
	store->objects[1].fd = fd;
	store->objects[1].generation = 1;
	store->objects[1].type = FILESYSTEMCMP_TYPE_DIRECTORY;
	if (!readonly && scan_directory(fd, max_bytes, max_objects,
	    &store->bytes, &store->nobjects) == -1) {
		int error;

		error = errno;
		disk_store_destroy(store);
		errno = error;
		return (-1);
	}
	*storep = store;
	return (0);
}

void
disk_store_destroy(struct disk_store *store)
{
	uint32_t i;

	if (store == NULL)
		return;
	for (i = 1; i <= store->limit; i++)
		if (store->objects[i].fd != -1)
			close(store->objects[i].fd);
	free(store->objects);
	explicit_bzero(store, sizeof(*store));
	free(store);
}

int
disk_root(struct disk_store *store, struct filesystemcmp_handle *handle)
{

	if (store == NULL || handle == NULL) {
		errno = EINVAL;
		return (-1);
	}
	handle->object = 1;
	handle->generation = store->objects[1].generation;
	return (0);
}

int
disk_lookup(struct disk_store *store, struct filesystemcmp_handle directory,
    const void *name, size_t length, struct filesystemcmp_handle *handle)
{
	struct disk_object *dir;
	struct stat status;
	char component[FILESYSTEMCMP_NAME_MAX + 1];
	uint32_t type;
	int fd, error;

	if (handle == NULL ||
	    valid_name(name, length, component) == -1)
		return (-1);
	dir = resolve(store, directory);
	if (dir == NULL)
		return (-1);
	if (dir->type != FILESYSTEMCMP_TYPE_DIRECTORY) {
		errno = ENOTDIR;
		return (-1);
	}
	fd = open_child(store, dir->fd, component, &status);
	if (fd == -1)
		return (-1);
	type = S_ISDIR(status.st_mode) ? FILESYSTEMCMP_TYPE_DIRECTORY :
	    FILESYSTEMCMP_TYPE_REGULAR;
	if (allocate(store, fd, type, handle) == -1) {
		error = errno;
		close(fd);
		errno = error;
		return (-1);
	}
	return (0);
}

int
disk_create(struct disk_store *store, struct filesystemcmp_handle directory,
    const void *name, size_t length, uint32_t flags, uint32_t mode,
    struct filesystemcmp_handle *handle)
{
	struct disk_object *dir;
	struct stat existing;
	char component[FILESYSTEMCMP_NAME_MAX + 1];
	uint32_t type;
	bool created;
	int fd, error, open_flags, unlink_flags;

	if (store == NULL || handle == NULL || store->readonly) {
		errno = store != NULL && store->readonly ? EROFS : EINVAL;
		return (-1);
	}
	if ((flags & ~FILESYSTEMCMP_CREATE_MASK) != 0 ||
	    valid_name(name, length, component) == -1)
		return (-1);
	dir = resolve(store, directory);
	if (dir == NULL)
		return (-1);
	if (dir->type != FILESYSTEMCMP_TYPE_DIRECTORY) {
		errno = ENOTDIR;
		return (-1);
	}
	created = false;
	if (fstatat(dir->fd, component, &existing,
	    AT_SYMLINK_NOFOLLOW) == -1) {
		if (errno != ENOENT)
			return (-1);
		if (store->nobjects >= store->limit) {
			errno = ENOSPC;
			return (-1);
		}
		created = true;
	} else if ((flags & FILESYSTEMCMP_CREATE_EXCLUSIVE) != 0) {
		errno = EEXIST;
		return (-1);
	}
	mode &= 0700;
	if ((flags & FILESYSTEMCMP_CREATE_DIRECTORY) != 0) {
		if (created &&
		    mkdirat(dir->fd, component, mode == 0 ? 0700 : mode) == -1)
			return (-1);
		fd = openat(dir->fd, component,
		    O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
		type = FILESYSTEMCMP_TYPE_DIRECTORY;
	} else {
		open_flags = O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW;
		if (created)
			open_flags |= O_EXCL;
		fd = openat(dir->fd, component, open_flags,
		    mode == 0 ? 0600 : mode);
		type = FILESYSTEMCMP_TYPE_REGULAR;
	}
	if (fd == -1) {
		error = errno;
		if (created) {
			unlink_flags = type == FILESYSTEMCMP_TYPE_DIRECTORY ?
			    AT_REMOVEDIR : 0;
			if (unlinkat(dir->fd, component, unlink_flags) == -1)
				error = EIO;
		}
		errno = error;
		return (-1);
	}
	if (allocate(store, fd, type, handle) == -1) {
		error = errno;
		close(fd);
		if (created) {
			unlink_flags = type == FILESYSTEMCMP_TYPE_DIRECTORY ?
			    AT_REMOVEDIR : 0;
			if (unlinkat(dir->fd, component, unlink_flags) == -1)
				error = EIO;
		}
		errno = error;
		return (-1);
	}
	if (created)
		store->nobjects++;
	return (0);
}

int
disk_open(struct disk_store *store, struct filesystemcmp_handle handle,
    uint32_t flags)
{
	struct disk_object *object;

	if (store == NULL || (flags & ~FILESYSTEMCMP_OPEN_MASK) != 0) {
		errno = EINVAL;
		return (-1);
	}
	object = resolve(store, handle);
	if (object == NULL)
		return (-1);
	if (store->readonly &&
	    (flags & (FILESYSTEMCMP_OPEN_WRITE |
	    FILESYSTEMCMP_OPEN_TRUNCATE)) != 0) {
		errno = EROFS;
		return (-1);
	}
	if ((flags & FILESYSTEMCMP_OPEN_TRUNCATE) != 0) {
		struct stat status;

		if (object->type != FILESYSTEMCMP_TYPE_REGULAR) {
			errno = EISDIR;
			return (-1);
		}
		if (fstat(object->fd, &status) == -1 ||
		    ftruncate(object->fd, 0) == -1)
			return (-1);
		store->bytes -= MIN(store->bytes, (uint64_t)status.st_size);
		return (0);
	}
	return (0);
}

ssize_t
disk_read(struct disk_store *store, struct filesystemcmp_handle handle,
    uint64_t offset, void *buffer, size_t length)
{
	struct disk_object *object;

	if (buffer == NULL || offset > OFF_MAX) {
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
	return (pread(object->fd, buffer, length, (off_t)offset));
}

ssize_t
disk_write(struct disk_store *store, struct filesystemcmp_handle handle,
    uint64_t offset, const void *buffer, size_t length)
{
	struct disk_object *object;
	struct stat before, after;
	uint64_t end, growth;
	ssize_t written;

	if (store == NULL || buffer == NULL || offset > OFF_MAX ||
	    length > store->max_file_bytes ||
	    offset > store->max_file_bytes - length) {
		errno = EINVAL;
		return (-1);
	}
	if (store->readonly) {
		errno = EROFS;
		return (-1);
	}
	object = resolve(store, handle);
	if (object == NULL)
		return (-1);
	if (object->type != FILESYSTEMCMP_TYPE_REGULAR) {
		errno = EISDIR;
		return (-1);
	}
	if (fstat(object->fd, &before) == -1)
		return (-1);
	if (before.st_nlink == 0) {
		errno = ESTALE;
		return (-1);
	}
	end = offset + length;
	growth = end > (uint64_t)before.st_size ?
	    end - (uint64_t)before.st_size : 0;
	if (growth > store->max_bytes - store->bytes) {
		errno = ENOSPC;
		return (-1);
	}
	written = pwrite(object->fd, buffer, length, (off_t)offset);
	if (written == -1)
		return (-1);
	if (fstat(object->fd, &after) == -1)
		return (-1);
	if (after.st_size > before.st_size)
		store->bytes += (uint64_t)(after.st_size - before.st_size);
	return (written);
}

int
disk_stat(struct disk_store *store, struct filesystemcmp_handle handle,
    struct filesystemcmp_stat_reply *reply)
{
	struct disk_object *object;
	struct stat status;

	if (reply == NULL) {
		errno = EINVAL;
		return (-1);
	}
	object = resolve(store, handle);
	if (object == NULL)
		return (-1);
	if (fstat(object->fd, &status) == -1)
		return (-1);
	memset(reply, 0, sizeof(*reply));
	reply->size = (uint64_t)status.st_size;
	reply->inode = (uint64_t)status.st_ino;
	reply->modified_sec = (uint64_t)status.st_mtim.tv_sec;
	reply->mode = (uint32_t)status.st_mode;
	reply->type = object->type;
	return (0);
}

int
disk_unlink(struct disk_store *store, struct filesystemcmp_handle directory,
    const void *name, size_t length)
{
	struct disk_object *dir;
	struct stat status;
	char component[FILESYSTEMCMP_NAME_MAX + 1];
	int flags;

	if (store == NULL || store->readonly) {
		errno = store != NULL ? EROFS : EINVAL;
		return (-1);
	}
	if (valid_name(name, length, component) == -1)
		return (-1);
	dir = resolve(store, directory);
	if (dir == NULL)
		return (-1);
	if (dir->type != FILESYSTEMCMP_TYPE_DIRECTORY) {
		errno = ENOTDIR;
		return (-1);
	}
	if (fstatat(dir->fd, component, &status, AT_SYMLINK_NOFOLLOW) == -1)
		return (-1);
	if (!S_ISREG(status.st_mode) && !S_ISDIR(status.st_mode)) {
		errno = EFTYPE;
		return (-1);
	}
	if (S_ISREG(status.st_mode) && status.st_nlink != 1) {
		errno = EMLINK;
		return (-1);
	}
	flags = S_ISDIR(status.st_mode) ? AT_REMOVEDIR : 0;
	if (unlinkat(dir->fd, component, flags) == -1)
		return (-1);
	if (store->nobjects > 1)
		store->nobjects--;
	if (S_ISREG(status.st_mode) &&
	    !object_is_open(store, status.st_dev, status.st_ino, NULL))
		store->bytes -= MIN(store->bytes, (uint64_t)status.st_size);
	return (0);
}

int
disk_rename(struct disk_store *store,
    struct filesystemcmp_handle old_directory, const void *old_name,
    size_t old_length, struct filesystemcmp_handle new_directory,
    const void *new_name, size_t new_length)
{
	struct disk_object *old_dir, *new_dir;
	char old_component[FILESYSTEMCMP_NAME_MAX + 1];
	char new_component[FILESYSTEMCMP_NAME_MAX + 1];
	struct stat status;

	if (store == NULL || store->readonly) {
		errno = store != NULL ? EROFS : EINVAL;
		return (-1);
	}
	if (valid_name(old_name, old_length, old_component) == -1 ||
	    valid_name(new_name, new_length, new_component) == -1)
		return (-1);
	old_dir = resolve(store, old_directory);
	new_dir = resolve(store, new_directory);
	if (old_dir == NULL || new_dir == NULL)
		return (-1);
	if (old_dir->type != FILESYSTEMCMP_TYPE_DIRECTORY ||
	    new_dir->type != FILESYSTEMCMP_TYPE_DIRECTORY) {
		errno = ENOTDIR;
		return (-1);
	}
	if (fstatat(new_dir->fd, new_component, &status,
	    AT_SYMLINK_NOFOLLOW) == 0) {
		errno = EEXIST;
		return (-1);
	}
	if (errno != ENOENT)
		return (-1);
	return (renameat(old_dir->fd, old_component, new_dir->fd,
	    new_component));
}

int
disk_close(struct disk_store *store, struct filesystemcmp_handle handle)
{
	struct disk_object *object;
	struct stat status;
	bool reclaim;

	object = resolve(store, handle);
	if (object == NULL)
		return (-1);
	if (handle.object == 1) {
		errno = EBUSY;
		return (-1);
	}
	reclaim = fstat(object->fd, &status) == 0 && S_ISREG(status.st_mode) &&
	    status.st_nlink == 0 &&
	    !object_is_open(store, status.st_dev, status.st_ino, object);
	close(object->fd);
	if (reclaim)
		store->bytes -= MIN(store->bytes, (uint64_t)status.st_size);
	object->fd = -1;
	object->type = 0;
	return (0);
}

int
disk_dup(struct disk_store *store, struct filesystemcmp_handle handle,
    struct filesystemcmp_handle *result)
{
	struct disk_object *object;
	int fd;

	if (store == NULL || result == NULL) {
		errno = EINVAL;
		return (-1);
	}
	object = resolve(store, handle);
	if (object == NULL)
		return (-1);
	fd = fcntl(object->fd, F_DUPFD_CLOEXEC, 0);
	if (fd == -1)
		return (-1);
	if (allocate(store, fd, object->type, result) == -1) {
		int error;

		error = errno;
		close(fd);
		errno = error;
		return (-1);
	}
	return (0);
}

int
disk_sync(struct disk_store *store, struct filesystemcmp_handle handle)
{
	struct disk_object *object;

	object = resolve(store, handle);
	if (object == NULL)
		return (-1);
	return (fsync(object->fd));
}
