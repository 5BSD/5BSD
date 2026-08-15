/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/endian.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "virtio_pmem_host.h"
#include "virtio_state_range.h"

#define	VIRTIO_PMEM_REQ_TYPE_FLUSH	0U

void
virtio_pmem_backing_init(struct virtio_pmem_backing *backing)
{

	if (backing == NULL)
		return;
	memset(backing, 0, sizeof(*backing));
	backing->fd = -1;
}

int
virtio_pmem_backing_open(struct virtio_pmem_backing *backing, const char *path)
{
	struct stat sb;
	void *mapping;
	size_t size;
	int error, fd;

	if (backing == NULL || path == NULL || path[0] == '\0' ||
	    backing->fd != -1 || backing->mapping != NULL || backing->size != 0)
		return (EINVAL);
	fd = open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
	if (fd == -1)
		return (errno);
	if (flock(fd, LOCK_EX | LOCK_NB) == -1) {
		error = errno;
		goto fail;
	}
	if (fstat(fd, &sb) == -1) {
		error = errno;
		goto fail_locked;
	}
	if (!S_ISREG(sb.st_mode) || sb.st_size <= 0 ||
	    (uintmax_t)sb.st_size > SIZE_MAX) {
		error = EINVAL;
		goto fail_locked;
	}
	size = (size_t)sb.st_size;
	mapping = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (mapping == MAP_FAILED) {
		error = errno;
		goto fail_locked;
	}

	backing->fd = fd;
	backing->mapping = mapping;
	backing->size = size;
	backing->device = sb.st_dev;
	backing->inode = sb.st_ino;
	return (0);

fail_locked:
	(void)flock(fd, LOCK_UN);
fail:
	(void)close(fd);
	return (error);
}

int
virtio_pmem_backing_flush(void *arg)
{
	struct virtio_pmem_backing *backing;
	struct stat sb;

	backing = arg;
	if (backing == NULL || backing->fd < 0 || backing->mapping == NULL ||
	    backing->size == 0)
		return (EINVAL);
	if (fstat(backing->fd, &sb) == -1)
		return (errno);
	if (!S_ISREG(sb.st_mode) || sb.st_dev != backing->device ||
	    sb.st_ino != backing->inode || sb.st_size <= 0 ||
	    (uintmax_t)sb.st_size != backing->size)
		return (EINVAL);
	if (msync(backing->mapping, backing->size, MS_SYNC) == -1)
		return (errno);
	if (fsync(backing->fd) == -1)
		return (errno);
	return (0);
}

void
virtio_pmem_backing_close(struct virtio_pmem_backing *backing)
{

	if (backing == NULL)
		return;
	if (backing->mapping != NULL && backing->size != 0)
		(void)munmap(backing->mapping, backing->size);
	if (backing->fd >= 0) {
		(void)flock(backing->fd, LOCK_UN);
		(void)close(backing->fd);
	}
	virtio_pmem_backing_init(backing);
}

int
virtio_pmem_config_encode(uint64_t start, uint64_t size,
    bool shared_memory_region, void *buffer, size_t buffer_size)
{
	uint8_t image[BHYVE_VIRTIO_PMEM_CONFIG_SIZE];

	if (buffer == NULL || buffer_size != sizeof(image))
		return (EINVAL);
	if (!shared_memory_region &&
	    (size == 0 || start > UINT64_MAX - (size - 1)))
		return (EINVAL);

	/*
	 * VirtIO 1.4 section 5.19.5.1 requires the physical range in the
	 * configuration unless feature bit zero selects shared-memory region
	 * ID zero.  In that mode the specification recommends canonical zeroes;
	 * emitting them also prevents stale destination addresses from becoming
	 * part of a portable device contract.
	 */
	memset(image, 0, sizeof(image));
	if (!shared_memory_region) {
		le64enc(image, start);
		le64enc(image + 8, size);
	}
	memcpy(buffer, image, sizeof(image));
	return (0);
}

int
virtio_pmem_request_decode(const void *request, size_t request_size)
{
	uint32_t type;

	if (request == NULL || request_size < BHYVE_VIRTIO_PMEM_REQUEST_SIZE)
		return (EINVAL);
	type = le32dec(request);
	return (type == VIRTIO_PMEM_REQ_TYPE_FLUSH ? 0 : EINVAL);
}

int
virtio_pmem_response_encode(int error, void *response,
    size_t response_capacity)
{
	uint8_t image[BHYVE_VIRTIO_PMEM_RESPONSE_SIZE];

	if (response == NULL || response_capacity < sizeof(image))
		return (EINVAL);
	/* Section 5.19.7.3 permits exactly zero or minus one on the wire. */
	le32enc(image, error == 0 ? 0 : UINT32_MAX);
	memcpy(response, image, sizeof(image));
	return (0);
}

int
virtio_pmem_process_request(const void *request, size_t request_size,
    void *response, size_t response_capacity, virtio_pmem_flush_cb flush,
    void *flush_arg, size_t *written)
{
	uint8_t image[BHYVE_VIRTIO_PMEM_RESPONSE_SIZE];
	int error;

	if (request == NULL || response == NULL || written == NULL ||
	    flush == NULL || request_size < BHYVE_VIRTIO_PMEM_REQUEST_SIZE ||
	    response_capacity < BHYVE_VIRTIO_PMEM_RESPONSE_SIZE)
		return (EINVAL);
	/*
	 * Decode, callback state, and publication are separate ownership
	 * domains.  Reject aliases before writing the length or invoking a
	 * persistence operation so malformed direct callers remain retryable.
	 */
	if (virtio_state_ranges_overlap(request, request_size, response,
	    response_capacity) ||
	    virtio_state_ranges_overlap(written, sizeof(*written), request,
	    request_size) ||
	    virtio_state_ranges_overlap(written, sizeof(*written), response,
	    response_capacity))
		return (EINVAL);

	*written = 0;
	error = virtio_pmem_request_decode(request, request_size);
	if (error == 0)
		error = flush(flush_arg);
	(void)virtio_pmem_response_encode(error, image, sizeof(image));
	memcpy(response, image, sizeof(image));
	*written = sizeof(image);
	return (0);
}
