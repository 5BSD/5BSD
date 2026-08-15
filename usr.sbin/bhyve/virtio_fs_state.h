/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_VIRTIO_FS_STATE_H_
#define	_BHYVE_VIRTIO_FS_STATE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "virtio_fs_backend.h"
#include "virtio_fs_host.h"

#define	VIRTIO_FS_STATE_MAGIC		0x31534656U	/* "VFS1" */
#define	VIRTIO_FS_STATE_VERSION		1U
#define	VIRTIO_FS_STATE_HEADER_SIZE	76U
#define	VIRTIO_FS_STATE_IDENTITY_MAX	4096U
#define	VIRTIO_FS_STATE_BACKEND_MAX	(64U * 1024U * 1024U)

struct virtio_fs_state_source {
	const void *tag;
	size_t tag_len;
	uint32_t num_request_queues;
	uint64_t negotiated_features;
	const struct virtio_fs_session *fuse_session;
	const struct virtio_fs_backend_session *backend_session;
	uint32_t pending_requests;
	const void *backend_identity;
	size_t backend_identity_len;
	const void *backend_state;
	size_t backend_state_len;
};

struct virtio_fs_state_decoded {
	uint32_t num_request_queues;
	uint64_t negotiated_features;
	struct virtio_fs_session fuse_session;
	uint64_t backend_incarnation;
	uint16_t backend_protocol_version;
	uint32_t backend_features;
	uint32_t backend_maximum_message;
	uint32_t backend_maximum_inflight;
	uint32_t backend_maximum_pending_bytes;
	const uint8_t *backend_state;
	size_t backend_state_len;
};

int	virtio_fs_state_size(const struct virtio_fs_state_source *, size_t *);
int	virtio_fs_state_encode(const struct virtio_fs_state_source *, void *,
	    size_t, size_t *);
int	virtio_fs_state_decode(const void *, size_t, const void *, size_t,
	    uint32_t, uint64_t, const void *, size_t,
	    const struct virtio_fs_backend_session *,
	    struct virtio_fs_state_decoded *);

#endif
