/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_VIRTIO_FS_BACKEND_H_
#define	_BHYVE_VIRTIO_FS_BACKEND_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define	VIRTIO_FS_BACKEND_MAGIC		0x42534656U	/* "VFSB" */
#define	VIRTIO_FS_BACKEND_VERSION	1U
#define	VIRTIO_FS_BACKEND_HEADER_SIZE	40U
#define	VIRTIO_FS_BACKEND_HELLO_SIZE	20U
#define	VIRTIO_FS_BACKEND_MAX_FRAME	(16U * 1024U * 1024U)
#define	VIRTIO_FS_BACKEND_MAX_INFLIGHT	65536U
#define	VIRTIO_FS_BACKEND_MAX_PENDING_BYTES (256U * 1024U * 1024U)

/*
 * The high request-id bit belongs to connection-control traffic.  Ordinary
 * FUSE dispatch identifiers are deliberately confined to the lower half so
 * replies can be routed without depending on message arrival order.
 */
#define	VIRTIO_FS_BACKEND_CONTROL_ID_BIT	(UINT64_C(1) << 63)
#define	VIRTIO_FS_BACKEND_REQUEST_ID_MAX	\
	(VIRTIO_FS_BACKEND_CONTROL_ID_BIT - 1)

#define	VIRTIO_FS_BACKEND_F_CANCEL	(UINT32_C(1) << 0)
#define	VIRTIO_FS_BACKEND_F_FREEZE	(UINT32_C(1) << 1)
#define	VIRTIO_FS_BACKEND_F_STATE_TRANSFER (UINT32_C(1) << 2)
#define	VIRTIO_FS_BACKEND_F_NOTIFICATION (UINT32_C(1) << 3)
#define	VIRTIO_FS_BACKEND_F_ALL		(VIRTIO_FS_BACKEND_F_CANCEL | \
					 VIRTIO_FS_BACKEND_F_FREEZE | \
					 VIRTIO_FS_BACKEND_F_STATE_TRANSFER | \
					 VIRTIO_FS_BACKEND_F_NOTIFICATION)

#define	VIRTIO_FS_BACKEND_MSG_F_NOREPLY	(UINT16_C(1) << 0)

enum virtio_fs_backend_message_type {
	VIRTIO_FS_BACKEND_HELLO = 1,
	VIRTIO_FS_BACKEND_HELLO_REPLY,
	VIRTIO_FS_BACKEND_REQUEST,
	VIRTIO_FS_BACKEND_RESPONSE,
	VIRTIO_FS_BACKEND_CANCEL,
	VIRTIO_FS_BACKEND_CANCEL_REPLY,
	VIRTIO_FS_BACKEND_QUIESCE,
	VIRTIO_FS_BACKEND_QUIESCE_REPLY,
	VIRTIO_FS_BACKEND_THAW,
	VIRTIO_FS_BACKEND_THAW_REPLY,
	VIRTIO_FS_BACKEND_SHUTDOWN,
	VIRTIO_FS_BACKEND_SHUTDOWN_REPLY,
	/* An unsolicited FUSE notification from an opted-in backend. */
	VIRTIO_FS_BACKEND_NOTIFICATION,
};

enum virtio_fs_backend_phase {
	VIRTIO_FS_BACKEND_DISCONNECTED = 0,
	VIRTIO_FS_BACKEND_NEGOTIATING,
	VIRTIO_FS_BACKEND_ACTIVE,
	VIRTIO_FS_BACKEND_QUIESCING,
	VIRTIO_FS_BACKEND_QUIESCED,
	VIRTIO_FS_BACKEND_THAWING,
	VIRTIO_FS_BACKEND_SHUTTING_DOWN,
	VIRTIO_FS_BACKEND_CLOSED,
};

struct virtio_fs_backend_header {
	uint16_t version;
	enum virtio_fs_backend_message_type type;
	uint16_t flags;
	uint32_t payload_len;
	uint64_t request_id;
	uint64_t incarnation;
	int32_t status;
};

struct virtio_fs_backend_hello {
	uint16_t minimum_version;
	uint16_t maximum_version;
	uint32_t features;
	uint32_t maximum_message;
	uint32_t maximum_inflight;
	uint32_t maximum_pending_bytes;
};

struct virtio_fs_backend_session {
	/* Protected by the owning backend connection lock. */
	enum virtio_fs_backend_phase phase;
	uint16_t version;
	uint32_t features;
	uint32_t maximum_message;
	uint32_t maximum_inflight;
	uint32_t maximum_pending_bytes;
	uint64_t incarnation;
	uint64_t pending_control_id;
	enum virtio_fs_backend_phase control_failure_phase;
};

int	virtio_fs_backend_header_encode(
	    const struct virtio_fs_backend_header *,
	    uint8_t[VIRTIO_FS_BACKEND_HEADER_SIZE]);
int	virtio_fs_backend_header_decode(const void *, size_t,
	    struct virtio_fs_backend_header *);
int	virtio_fs_backend_hello_encode(const struct virtio_fs_backend_hello *,
	    uint8_t[VIRTIO_FS_BACKEND_HELLO_SIZE]);
int	virtio_fs_backend_hello_decode(const void *, size_t,
	    struct virtio_fs_backend_hello *);
void	virtio_fs_backend_session_init(struct virtio_fs_backend_session *);
int	virtio_fs_backend_start_hello(struct virtio_fs_backend_session *,
	    uint64_t, const struct virtio_fs_backend_hello *);
int	virtio_fs_backend_finish_hello(struct virtio_fs_backend_session *,
	    const struct virtio_fs_backend_header *,
	    const struct virtio_fs_backend_hello *);
int	virtio_fs_backend_start_control(struct virtio_fs_backend_session *,
	    enum virtio_fs_backend_message_type, uint64_t);
int	virtio_fs_backend_finish_control(struct virtio_fs_backend_session *,
	    const struct virtio_fs_backend_header *);
void	virtio_fs_backend_disconnect(struct virtio_fs_backend_session *);

#endif
