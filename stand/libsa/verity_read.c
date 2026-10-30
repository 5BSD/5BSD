/* SPDX-License-Identifier: BSD-2-Clause */
#include <stand.h>
#include <stdint.h>
#include <sys/stat.h>
#include "verity_read.h"

int
verity_file_init(struct verity_file *file, int fd,
    const struct g_verity_root *root, uint64_t *tags, void *blocks,
    size_t entries, void *data, void *hashes)
{
	struct verity_file fresh;
	struct stat st;
	int error;

	if (file == NULL || root == NULL || fd < 0 || data == NULL ||
	    hashes == NULL || data == hashes)
		return (EINVAL);
	if (root->layout.data_bytes > INT64_MAX ||
	    root->layout.tree_bytes > INT64_MAX - root->layout.data_bytes)
		return (EINVAL);
	if (fstat(fd, &st) != 0)
		return (errno);
	if (!S_ISREG(st.st_mode) || st.st_size < 0 ||
	    (uint64_t)st.st_size != root->layout.data_bytes + root->layout.tree_bytes)
		return (EINVAL);
	memset(&fresh, 0, sizeof(fresh));
	error = g_verity_cache_init(&fresh.cache, root, tags, blocks, entries);
	if (error != 0)
		return (error);
	fresh.fd = fd;
	fresh.data = data;
	fresh.hashes = hashes;
	*file = fresh;
	return (0);
}

static int
verity_file_block(void *arg, int tree, uint64_t offset, void *buffer,
    size_t length)
{
	struct verity_file *file = arg;
	const struct g_verity_layout *layout = &file->cache.root.layout;
	uint64_t bytes, base;
	size_t done;
	ssize_t count;

	if ((tree != 0 && tree != 1) || length != layout->block_size)
		return (EINVAL);
	bytes = tree ? layout->tree_bytes : layout->data_bytes;
	base = tree ? layout->data_bytes : 0;
	if (offset > bytes || length > bytes - offset)
		return (EINVAL);
	if (lseek(file->fd, base + offset, SEEK_SET) == -1)
		return (errno);
	for (done = 0; done < length; done += count) {
		count = read(file->fd, (char *)buffer + done, length - done);
		if (count < 0)
			return (errno);
		if (count == 0)
			return (EIO);
	}
	return (0);
}

int
verity_file_read(struct verity_file *file, uint64_t offset, size_t length,
    void *output)
{
	int error;

	if (file == NULL || file->cache.initialized != 1)
		return (EINVAL);
	/* Refuse a recursive backing-file dependency, not a locking protocol. */
	if (file->busy != 0)
		return (EDEADLK);
	file->busy = 1;
	error = g_verity_cached_read_range(&file->cache, offset, length,
	    verity_file_block, file, file->data, file->hashes, output);
	file->busy = 0;
	return (error);
}
