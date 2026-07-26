/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "checkpoint_manifest.h"

bool
checkpoint_member_valid(const char *member)
{
	size_t len;

	len = strnlen(member, NAME_MAX + 1);
	return (len > 0 && len <= NAME_MAX && strcmp(member, ".") != 0 &&
	    strcmp(member, "..") != 0 && strchr(member, '/') == NULL);
}

static bool
checkpoint_generation_member_valid(const char *base, const char *role,
    const char *member, const char **generation)
{
	const char *cursor;
	size_t base_len, member_len, prefix_len, role_len;

	base_len = strlen(base);
	role_len = strlen(role);
	if (base_len > NAME_MAX ||
	    base_len > SIZE_MAX - role_len - 2)
		return (false);
	prefix_len = base_len + 1 + role_len + 1;
	member_len = strlen(member);
	if (prefix_len > member_len ||
	    member_len != prefix_len + CHECKPOINT_GENERATION_HEX_LEN ||
	    strncmp(member, base, base_len) != 0 ||
	    member[base_len] != '.' ||
	    strncmp(member + base_len + 1, role, role_len) != 0 ||
	    member[base_len + 1 + role_len] != '.')
		return (false);
	cursor = member + prefix_len;
	for (unsigned int i = 0; i < CHECKPOINT_GENERATION_HEX_LEN; i++) {
		if (!((cursor[i] >= '0' && cursor[i] <= '9') ||
		    (cursor[i] >= 'a' && cursor[i] <= 'f') ||
		    (cursor[i] >= 'A' && cursor[i] <= 'F')))
			return (false);
	}
	if (generation != NULL)
		*generation = cursor;
	return (true);
}

bool
checkpoint_manifest_valid_for(const char *base,
    const struct checkpoint_manifest *m)
{
	const char *data_generation, *kern_generation, *meta_generation;

	if (!checkpoint_generation_member_valid(base, "data", m->data,
	    &data_generation) ||
	    !checkpoint_generation_member_valid(base, "kern", m->kern,
	    &kern_generation) ||
	    !checkpoint_generation_member_valid(base, "meta", m->meta,
	    &meta_generation))
		return (false);
	return (strncmp(data_generation, kern_generation,
	    CHECKPOINT_GENERATION_HEX_LEN) == 0 &&
	    strncmp(data_generation, meta_generation,
	    CHECKPOINT_GENERATION_HEX_LEN) == 0);
}

static int
checkpoint_manifest_read_fd(int fd, struct checkpoint_manifest *m,
    bool *is_manifest)
{
	char buffer[sizeof(CHECKPOINT_MANIFEST_MAGIC) + 3 * (NAME_MAX + 8)];
	char *cursor, *end, *line;
	size_t used;
	ssize_t nread;
	int error;

	*is_manifest = false;
	used = 0;
	error = 0;
	while (used < sizeof(buffer)) {
		do {
			nread = read(fd, buffer + used, sizeof(buffer) - used);
		} while (nread < 0 && errno == EINTR);
		if (nread < 0) {
			error = errno;
			break;
		}
		if (nread == 0)
			break;
		used += (size_t)nread;
	}
	if (error != 0)
		return (error);
	if (used < strlen(CHECKPOINT_MANIFEST_MAGIC) ||
	    memcmp(buffer, CHECKPOINT_MANIFEST_MAGIC,
	    strlen(CHECKPOINT_MANIFEST_MAGIC)) != 0)
		return (0);
	if (used == sizeof(buffer))
		return (EINVAL);

	buffer[used] = '\0';
	memset(m, 0, sizeof(*m));
	cursor = buffer + strlen(CHECKPOINT_MANIFEST_MAGIC);
	end = buffer + used;
	for (unsigned int field = 0; field < 3; field++) {
		const char *prefix;
		char *destination;
		size_t prefix_len, value_len;

		line = strchr(cursor, '\n');
		if (line == NULL || line > end)
			return (EINVAL);
		*line = '\0';
		if (field == 0) {
			prefix = "data=";
			destination = m->data;
		} else if (field == 1) {
			prefix = "kern=";
			destination = m->kern;
		} else {
			prefix = "meta=";
			destination = m->meta;
		}
		prefix_len = strlen(prefix);
		if (strncmp(cursor, prefix, prefix_len) != 0)
			return (EINVAL);
		value_len = strlen(cursor + prefix_len);
		if (value_len == 0 || value_len > NAME_MAX)
			return (EINVAL);
		memcpy(destination, cursor + prefix_len, value_len + 1);
		if (!checkpoint_member_valid(destination))
			return (EINVAL);
		cursor = line + 1;
	}
	if (cursor != end)
		return (EINVAL);
	*is_manifest = true;
	return (0);
}

int
checkpoint_manifest_read(const char *filename, struct checkpoint_manifest *m,
    bool *is_manifest)
{
	int fd, error;

	fd = open(filename, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return (errno);
	error = checkpoint_manifest_read_fd(fd, m, is_manifest);
	if (close(fd) != 0 && error == 0)
		error = errno;
	return (error);
}

int
checkpoint_manifest_read_at(int dirfd, const char *filename,
    struct checkpoint_manifest *m, bool *exists, bool *is_manifest)
{
	int fd, error;

	*exists = false;
	*is_manifest = false;
	fd = openat(dirfd, filename, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return (errno == ENOENT ? 0 : errno);
	*exists = true;
	error = checkpoint_manifest_read_fd(fd, m, is_manifest);
	if (close(fd) != 0 && error == 0)
		error = errno;
	return (error);
}

char *
checkpoint_member_path(const char *checkpoint, const char *member)
{
	char *copy, *directory, *path;

	copy = strdup(checkpoint);
	if (copy == NULL)
		return (NULL);
	directory = dirname(copy);
	if (asprintf(&path, "%s/%s", directory, member) < 0)
		path = NULL;
	free(copy);
	return (path);
}

int
checkpoint_generation_names(const char *base, struct checkpoint_manifest *m,
    char **manifest_tmp)
{
	uint32_t random_words[4];
	char generation[CHECKPOINT_GENERATION_HEX_LEN + 1];
	int length;

	*manifest_tmp = NULL;
	if (!checkpoint_member_valid(base))
		return (EINVAL);
	arc4random_buf(random_words, sizeof(random_words));
	length = snprintf(generation, sizeof(generation), "%08x%08x%08x%08x",
	    random_words[0], random_words[1], random_words[2], random_words[3]);
	if (length != CHECKPOINT_GENERATION_HEX_LEN)
		return (EIO);
	length = snprintf(m->data, sizeof(m->data), "%s.data.%s", base,
	    generation);
	if (length < 0 || (size_t)length >= sizeof(m->data))
		goto name_too_long;
	length = snprintf(m->kern, sizeof(m->kern), "%s.kern.%s", base,
	    generation);
	if (length < 0 || (size_t)length >= sizeof(m->kern))
		goto name_too_long;
	length = snprintf(m->meta, sizeof(m->meta), "%s.meta.%s", base,
	    generation);
	if (length < 0 || (size_t)length >= sizeof(m->meta))
		goto name_too_long;
	if (asprintf(manifest_tmp, "%s.manifest.%s.tmp", base, generation) < 0)
		return (ENOMEM);
	if (strlen(*manifest_tmp) > NAME_MAX) {
		free(*manifest_tmp);
		*manifest_tmp = NULL;
		goto name_too_long;
	}
	return (0);

name_too_long:
	return (ENAMETOOLONG);
}

static int
checkpoint_write_all(int fd, const void *buffer, size_t length)
{
	const uint8_t *cursor;
	ssize_t written;

	cursor = buffer;
	while (length != 0) {
		written = write(fd, cursor, length);
		if (written < 0) {
			if (errno == EINTR)
				continue;
			return (errno);
		}
		if (written == 0)
			return (EIO);
		cursor += written;
		length -= (size_t)written;
	}
	return (0);
}

int
checkpoint_publish(int dirfd, const char *checkpoint_file,
    const char *manifest_tmp, const struct checkpoint_manifest *m,
    bool *published)
{
	char contents[sizeof(CHECKPOINT_MANIFEST_MAGIC) +
	    3 * (NAME_MAX + 8)];
	int fd, error, length;

	length = snprintf(contents, sizeof(contents),
	    CHECKPOINT_MANIFEST_MAGIC "data=%s\nkern=%s\nmeta=%s\n",
	    m->data, m->kern, m->meta);
	if (length < 0 || (size_t)length >= sizeof(contents))
		return (EOVERFLOW);

	*published = false;
	fd = openat(dirfd, manifest_tmp,
	    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0700);
	if (fd < 0)
		return (errno);
	error = checkpoint_write_all(fd, contents, (size_t)length);
	if (error == 0 && fsync(fd) != 0)
		error = errno != 0 ? errno : EIO;
	if (close(fd) != 0 && error == 0)
		error = errno != 0 ? errno : EIO;
	if (error == 0 && renameat(dirfd, manifest_tmp, dirfd,
	    checkpoint_file) != 0) {
		error = errno;
	} else if (error == 0) {
		*published = true;
	}
	if (error == 0 && fsync(dirfd) != 0)
		error = errno != 0 ? errno : EIO;
	if (error != 0)
		(void)unlinkat(dirfd, manifest_tmp, 0);
	return (error);
}
