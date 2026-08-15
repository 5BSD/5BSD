/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_VIRTIO_FS_HOST_H_
#define	_BHYVE_VIRTIO_FS_HOST_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define	BHYVE_VIRTIO_FS_MAX_MESSAGE	(16U * 1024U * 1024U)
#define	BHYVE_VIRTIO_FS_TAG_SIZE	36U
#define	BHYVE_VIRTIO_FS_CONFIG_BASE_SIZE	40U
#define	BHYVE_VIRTIO_FS_CONFIG_SIZE	44U
#define	BHYVE_VIRTIO_FS_F_NOTIFICATION	UINT64_C(1)

/*
 * A notification buffer must hold a complete FUSE notification.  This is a
 * device contract, not an assumption about the host page size: it is carried
 * in the optional VirtIO 1.4 notify_buf_size configuration field whenever
 * VIRTIO_FS_F_NOTIFICATION is offered.
 */
#define	BHYVE_VIRTIO_FS_NOTIFY_BUF_SIZE	(64U * 1024U)

enum virtio_fs_byte_order {
	VIRTIO_FS_BYTE_ORDER_UNKNOWN = 0,
	VIRTIO_FS_BYTE_ORDER_LITTLE,
	VIRTIO_FS_BYTE_ORDER_BIG,
};

enum virtio_fs_queue_class {
	VIRTIO_FS_QUEUE_REQUEST = 0,
	VIRTIO_FS_QUEUE_HIPRIO,
};

struct virtio_fs_session {
	/* Protected by the owning device/backend session lock. */
	enum virtio_fs_byte_order byte_order;
	bool initialized;
	uint64_t incarnation;
};

struct virtio_fs_request_context {
	enum virtio_fs_byte_order byte_order;
	uint32_t opcode;
	uint32_t init_major;
	uint64_t unique;
	uint64_t incarnation;
	bool expects_reply;
	bool initializes;
};

typedef int (*virtio_fs_backend_request_cb)(void *, const void *, size_t,
    void *, size_t, size_t *);

void	virtio_fs_session_reset(struct virtio_fs_session *);
int	virtio_fs_config_encode(const void *, size_t, uint32_t,
	    uint8_t[BHYVE_VIRTIO_FS_CONFIG_SIZE]);
int	virtio_fs_config_encode_notification(const void *, size_t, uint32_t,
	    uint32_t, uint8_t[BHYVE_VIRTIO_FS_CONFIG_SIZE]);
int	virtio_fs_request_accept(struct virtio_fs_session *,
	    enum virtio_fs_queue_class, const void *, size_t, size_t,
	    struct virtio_fs_request_context *);
int	virtio_fs_response_complete(struct virtio_fs_session *,
	    const struct virtio_fs_request_context *, const void *, size_t);
int	virtio_fs_process_request(struct virtio_fs_session *,
	    enum virtio_fs_queue_class, const void *, size_t, void *, size_t,
	    virtio_fs_backend_request_cb, void *, size_t *);

#endif
