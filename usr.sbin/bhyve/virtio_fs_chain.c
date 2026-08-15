/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/uio.h>

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "virtio_fs_chain.h"

static int
virtio_fs_chain_total(const struct iovec *iov, size_t count, size_t limit,
    size_t *total)
{
	size_t sum;

	sum = 0;
	for (size_t i = 0; i < count; i++) {
		if (iov[i].iov_base == NULL && iov[i].iov_len != 0)
			return (EFAULT);
		if (iov[i].iov_len > limit - sum)
			return (limit == SIZE_MAX ? EOVERFLOW : EMSGSIZE);
		sum += iov[i].iov_len;
	}
	*total = sum;
	return (0);
}

int
virtio_fs_chain_validate(const struct iovec *iov, size_t iov_count,
    size_t readable_count, size_t writable_count, bool ordered,
    size_t maximum_message, struct virtio_fs_chain *chain)
{
	size_t request_length, response_capacity;
	int error;

	if (iov == NULL || chain == NULL || maximum_message == 0 ||
	    readable_count == 0 || readable_count > iov_count ||
	    writable_count > iov_count - readable_count ||
	    readable_count + writable_count != iov_count || !ordered)
		return (EINVAL);
	error = virtio_fs_chain_total(iov, readable_count, maximum_message,
	    &request_length);
	if (error != 0)
		return (error);
	/*
	 * Only response bytes emitted by the backend are message-bounded.
	 * A driver may legally provide more writable capacity, so validate its
	 * arithmetic without rejecting a harmless oversized destination.
	 */
	error = virtio_fs_chain_total(iov + readable_count, writable_count,
	    SIZE_MAX, &response_capacity);
	if (error != 0)
		return (error);
	if (request_length == 0)
		return (EINVAL);
	*chain = (struct virtio_fs_chain) {
		.readable_iov = iov,
		.writable_iov = iov + readable_count,
		.readable_count = readable_count,
		.writable_count = writable_count,
		.request_length = request_length,
		.response_capacity = response_capacity,
	};
	return (0);
}

int
virtio_fs_chain_gather(const struct virtio_fs_chain *chain, void *buffer,
    size_t buffer_size)
{
	size_t copied;

	if (chain == NULL || (buffer == NULL && buffer_size != 0) ||
	    buffer_size != chain->request_length)
		return (EINVAL);
	copied = 0;
	for (size_t i = 0; i < chain->readable_count; i++) {
		if (chain->readable_iov[i].iov_len > buffer_size - copied)
			return (EPROTO);
		memcpy((uint8_t *)buffer + copied,
		    chain->readable_iov[i].iov_base,
		    chain->readable_iov[i].iov_len);
		copied += chain->readable_iov[i].iov_len;
	}
	return (copied == buffer_size ? 0 : EPROTO);
}

int
virtio_fs_chain_scatter(const struct virtio_fs_chain *chain,
    const void *buffer, size_t buffer_size)
{
	size_t copied, count;

	if (chain == NULL || (buffer == NULL && buffer_size != 0))
		return (EINVAL);
	if (buffer_size > chain->response_capacity)
		return (EMSGSIZE);
	copied = 0;
	for (size_t i = 0; i < chain->writable_count &&
	    copied < buffer_size; i++) {
		count = chain->writable_iov[i].iov_len;
		if (count > buffer_size - copied)
			count = buffer_size - copied;
		memcpy(chain->writable_iov[i].iov_base,
		    (const uint8_t *)buffer + copied, count);
		copied += count;
	}
	return (copied == buffer_size ? 0 : EPROTO);
}
