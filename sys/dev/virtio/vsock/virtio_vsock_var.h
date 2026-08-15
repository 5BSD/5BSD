/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _DEV_VIRTIO_VSOCK_VIRTIO_VSOCK_VAR_H_
#define _DEV_VIRTIO_VSOCK_VIRTIO_VSOCK_VAR_H_

#include <sys/types.h>

/*
 * A used-ring length is device supplied.  Keep these predicates in a small
 * transport-independent header so malformed completion boundaries can be
 * tested without instantiating the socket domain or a virtqueue.
 */
static inline bool
virtio_vsock_rx_used_len_valid(uint32_t used_len, uint32_t buffer_len)
{

	return (used_len <= buffer_len);
}

static inline bool
virtio_vsock_event_used_len_valid(uint32_t used_len, uint32_t event_len)
{

	return (used_len == event_len);
}

#endif /* _DEV_VIRTIO_VSOCK_VIRTIO_VSOCK_VAR_H_ */
