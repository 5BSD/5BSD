/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/uio.h>

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "virtio_pmem_host.h"
#include "virtio_pmem_queue.h"

static int
virtio_pmem_iov_total(const struct iovec *iov, int niov, size_t *total)
{
	size_t result;

	if (iov == NULL || niov <= 0 || total == NULL)
		return (EINVAL);
	result = 0;
	for (int i = 0; i < niov; i++) {
		if ((iov[i].iov_base == NULL && iov[i].iov_len != 0) ||
		    iov[i].iov_len > SIZE_MAX - result)
			return (EINVAL);
		result += iov[i].iov_len;
	}
	*total = result;
	return (0);
}

int
virtio_pmem_chain_prepare(const struct iovec *iov, int niov, int readable,
    int writable, struct virtio_pmem_chain *chain)
{
	int error;
	size_t copied, length, readable_bytes, remaining, writable_bytes;

	if (iov == NULL || chain == NULL || niov <= 0 || readable <= 0 ||
	    writable <= 0 || readable > niov || writable > niov - readable ||
	    readable + writable != niov)
		return (EINVAL);
	error = virtio_pmem_iov_total(iov, readable, &readable_bytes);
	if (error != 0)
		return (error);
	error = virtio_pmem_iov_total(iov + readable, writable,
	    &writable_bytes);
	if (error != 0)
		return (error);
	if (readable_bytes < sizeof(chain->request) ||
	    writable_bytes < BHYVE_VIRTIO_PMEM_RESPONSE_SIZE)
		return (EMSGSIZE);

	memset(chain, 0, sizeof(*chain));
	copied = 0;
	for (int i = 0; i < readable && copied != sizeof(chain->request); i++) {
		length = MIN(iov[i].iov_len, sizeof(chain->request) - copied);
		memcpy(chain->request + copied, iov[i].iov_base, length);
		copied += length;
	}
	if (copied != sizeof(chain->request))
		return (EMSGSIZE);

	remaining = BHYVE_VIRTIO_PMEM_RESPONSE_SIZE;
	for (int i = 0; i < writable && remaining != 0; i++) {
		length = MIN(iov[readable + i].iov_len, remaining);
		if (length == 0)
			continue;
		chain->response[chain->response_count].iov_base =
		    iov[readable + i].iov_base;
		chain->response[chain->response_count].iov_len = length;
		chain->response_count++;
		remaining -= length;
	}
	return (remaining == 0 ? 0 : EMSGSIZE);
}

int
virtio_pmem_chain_complete(const struct virtio_pmem_chain *chain, int error,
    size_t *written)
{
	uint8_t response[BHYVE_VIRTIO_PMEM_RESPONSE_SIZE];
	size_t copied;

	if (chain == NULL || written == NULL || chain->response_count == 0 ||
	    chain->response_count > nitems(chain->response))
		return (EINVAL);
	if (virtio_pmem_response_encode(error, response, sizeof(response)) != 0)
		return (EINVAL);
	copied = 0;
	for (size_t i = 0; i < chain->response_count; i++) {
		if (chain->response[i].iov_base == NULL ||
		    chain->response[i].iov_len == 0 ||
		    chain->response[i].iov_len > sizeof(response) - copied)
			return (EINVAL);
		memcpy(chain->response[i].iov_base, response + copied,
		    chain->response[i].iov_len);
		copied += chain->response[i].iov_len;
	}
	if (copied != sizeof(response))
		return (EINVAL);
	*written = copied;
	return (0);
}
