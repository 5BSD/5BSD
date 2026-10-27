/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bio.h>
#include <sys/errno.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/malloc.h>
#include <geom/geom.h>
#include <geom/verity/g_verity_io.h>

int
g_verity_backing_bind(struct g_verity_backing *backing, struct g_consumer *cp,
    uint64_t bytes, uint32_t block)
{
	struct g_verity_layout layout;
	struct g_provider *pp;
	int error;

	g_topology_assert();
	if (backing == NULL || cp == NULL || cp->provider == NULL || cp->acr < 1)
		return (EINVAL);
	error = g_verity_layout(bytes, block, &layout);
	if (error != 0)
		return (error);
	pp = cp->provider;
	if (layout.tree_bytes > (uint64_t)INT64_MAX - bytes ||
	    pp->mediasize != (off_t)(bytes + layout.tree_bytes) ||
	    pp->sectorsize == 0 || block % pp->sectorsize != 0 || block > maxphys)
		return (EINVAL);
	backing->consumer = cp;
	backing->data_bytes = bytes;
	backing->tree_bytes = layout.tree_bytes;
	backing->block_size = block;
	return (0);
}

static int
backing_read_extent(void *arg, int tree, uint64_t offset, void *buffer,
    size_t length)
{
	struct g_verity_backing *backing = arg;
	struct bio *bp;
	uint64_t bytes, base;
	int error;

	g_topology_assert_not();
	if (backing == NULL || buffer == NULL || (tree != 0 && tree != 1))
		return (EINVAL);
	bytes = tree ? backing->tree_bytes : backing->data_bytes;
	base = tree ? backing->data_bytes : 0;
	if (backing->block_size == 0 || length == 0 || length > maxphys ||
	    length % backing->block_size != 0 ||
	    offset % backing->block_size != 0 || offset > bytes ||
	    length > bytes - offset)
		return (EINVAL);
	/* Bind checked the complete extent; the owner keeps it immutable. */
	bp = g_alloc_bio();
	bp->bio_cmd = BIO_READ;
	bp->bio_done = NULL;
	bp->bio_offset = base + offset;
	bp->bio_length = length;
	bp->bio_data = buffer;
	g_io_request(bp, backing->consumer);
	error = biowait(bp, "gverity");
	if (error == 0 && bp->bio_completed != length)
		error = EIO;
	g_destroy_bio(bp);
	return (error);
}

int
g_verity_backing_read(void *arg, int tree, uint64_t offset, void *buffer,
    size_t length)
{
	struct g_verity_backing *backing = arg;

	if (backing == NULL || length != backing->block_size)
		return (EINVAL);
	return (backing_read_extent(arg, tree, offset, buffer, length));
}

int
g_verity_window_init(struct g_verity_read_window *window,
    struct g_verity_backing *backing, uint64_t offset, size_t length,
    void *buffer, size_t capacity)
{
	struct g_verity_read_window initialized;
	uint64_t end;
	uint32_t block;

	g_topology_assert_not();
	if (window == NULL || backing == NULL || buffer == NULL || length == 0)
		return (EINVAL);
	block = backing->block_size;
	if (block == 0 || capacity < block || capacity > maxphys ||
	    capacity % block != 0 || offset >= backing->data_bytes ||
	    length > backing->data_bytes - offset)
		return (EINVAL);
	/* Bound by the already block-aligned data extent, avoiding overflow. */
	end = offset + length;
	if (end % block != 0)
		end += block - end % block;
	memset(&initialized, 0, sizeof(initialized));
	initialized.backing = backing;
	initialized.buffer = buffer;
	initialized.first = offset - offset % block;
	initialized.end = end;
	initialized.capacity = capacity;
	*window = initialized;
	return (0);
}

int
g_verity_window_read(void *arg, int tree, uint64_t offset, void *buffer,
    size_t length)
{
	struct g_verity_read_window *window = arg;
	size_t count;
	int error;

	g_topology_assert_not();
	if (window == NULL || window->backing == NULL || buffer == NULL ||
	    length != window->backing->block_size || length == 0 ||
	    (tree != 0 && tree != 1))
		return (EINVAL);
	if (tree)
		return (g_verity_backing_read(window->backing, tree, offset,
		    buffer, length));
	if (offset % length != 0 || offset < window->first ||
	    offset >= window->end || length > window->end - offset)
		return (EINVAL);
	if (window->valid == 0 || offset < window->cached_offset ||
	    offset - window->cached_offset >= window->valid) {
		window->valid = 0;
		count = MIN((uint64_t)window->capacity, window->end - offset);
		error = backing_read_extent(window->backing, 0, offset,
		    window->buffer, count);
		if (error != 0)
			return (error);
		window->cached_offset = offset;
		window->valid = count;
	}
	memcpy(buffer, (char *)window->buffer + offset - window->cached_offset,
	    length);
	return (0);
}
