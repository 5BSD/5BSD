/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/stat.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "run_container_cleanup.h"

struct cleanup_frame {
	DIR *dir;
	char *name;
};

static int
is_dot(const char *name)
{
	return (strcmp(name, ".") == 0 || strcmp(name, "..") == 0);
}

/* Return a directory fd, -2 when removed/absent, or -1 on failure. */
static int
remove_or_open(int parent, const char *name, dev_t device)
{
	struct stat st;
	int fd, saved;

	if (fstatat(parent, name, &st, AT_SYMLINK_NOFOLLOW) == -1)
		return (errno == ENOENT ? -2 : -1);
	if (st.st_dev != device)
		return (errno = EXDEV, -1);
	if (!S_ISDIR(st.st_mode)) {
		if (unlinkat(parent, name, 0) == -1 && errno != ENOENT)
			return (-1);
		return (-2);
	}
	fd = openat(parent, name,
	    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (fd == -1)
		return (-1);
	if (fstat(fd, &st) == -1) {
		saved = errno;
		close(fd);
		return (errno = saved, -1);
	}
	if (st.st_dev != device) {
		close(fd);
		return (errno = EXDEV, -1);
	}
	return (fd);
}

int
sb_run_container_remove_at(int parent, const char *name)
{
	struct cleanup_frame *frames = NULL, *next;
	struct stat st;
	struct dirent *entry;
	DIR *dir;
	char *leaf;
	size_t depth = 0, capacity = 0, next_capacity;
	int fd, ancestor, saved;

	if (name == NULL || *name == '\0' || is_dot(name) ||
	    strchr(name, '/') != NULL)
		return (errno = EINVAL, -1);
	if (fstat(parent, &st) == -1)
		return (-1);
	fd = remove_or_open(parent, name, st.st_dev);
	if (fd < 0)
		return (fd == -2 ? 0 : -1);
	leaf = strdup(name);
	if (leaf == NULL) {
		saved = errno;
		close(fd);
		return (errno = saved, -1);
	}
	for (;;) {
		/* Iterative traversal: service-controlled nesting must not exhaust
		 * the manager's C stack. Allocation/fd exhaustion is a clean error. */
		if (depth == capacity) {
			if (capacity > SIZE_MAX / 2) {
				saved = ENOMEM;
				free(leaf);
				close(fd);
				goto fail;
			}
			next_capacity = capacity == 0 ? 16 : capacity * 2;
			next = reallocarray(frames, next_capacity, sizeof(*frames));
			if (next == NULL) {
				saved = errno;
				free(leaf);
				close(fd);
				goto fail;
			}
			frames = next;
			capacity = next_capacity;
		}
		dir = fdopendir(fd);
		if (dir == NULL) {
			saved = errno;
			free(leaf);
			close(fd);
			goto fail;
		}
		frames[depth++] = (struct cleanup_frame){dir, leaf};
		while (depth != 0) {
			dir = frames[depth - 1].dir;
			errno = 0;
			entry = readdir(dir);
			if (entry == NULL) {
				if (errno != 0) {
					saved = errno;
					goto fail;
				}
				ancestor = depth == 1 ? parent :
				    dirfd(frames[depth - 2].dir);
				leaf = frames[depth - 1].name;
				depth--;
				if (closedir(dir) == -1) {
					saved = errno;
					free(leaf);
					goto fail;
				}
				if (unlinkat(ancestor, leaf, AT_REMOVEDIR) == -1 &&
				    errno != ENOENT) {
					saved = errno;
					free(leaf);
					goto fail;
				}
				free(leaf);
				continue;
			}
			if (is_dot(entry->d_name))
				continue;
			fd = remove_or_open(dirfd(dir), entry->d_name, st.st_dev);
			if (fd == -1) {
				saved = errno;
				goto fail;
			}
			if (fd == -2)
				continue;
			leaf = strdup(entry->d_name);
			if (leaf == NULL) {
				saved = errno;
				close(fd);
				goto fail;
			}
			break;
		}
		if (depth == 0) {
			free(frames);
			return (0);
		}
	}
fail:
	while (depth != 0) {
		depth--;
		closedir(frames[depth].dir);
		free(frames[depth].name);
	}
	free(frames);
	return (errno = saved, -1);
}

int
sb_run_container_sweep_at(int parent)
{
	struct dirent *entry;
	DIR *dir;
	int fd, saved;

	/* An independent open description leaves the caller's directory offset
	 * unchanged, including when initialization must be retried. */
	fd = openat(parent, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd == -1)
		return (-1);
	dir = fdopendir(fd);
	if (dir == NULL) {
		saved = errno;
		close(fd);
		return (errno = saved, -1);
	}
	for (;;) {
		errno = 0;
		entry = readdir(dir);
		if (entry == NULL) {
			saved = errno;
			break;
		}
		if (!is_dot(entry->d_name) &&
		    sb_run_container_remove_at(parent, entry->d_name) == -1) {
			saved = errno;
			break;
		}
	}
	if (closedir(dir) == -1 && saved == 0)
		saved = errno;
	return (saved == 0 ? 0 : (errno = saved, -1));
}
