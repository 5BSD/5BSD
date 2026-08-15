/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_VIRTIO_FS_DISPATCH_H_
#define	_BHYVE_VIRTIO_FS_DISPATCH_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "virtio_fs_backend.h"
#include "virtio_fs_host.h"
#include "virtio_fs_pending.h"

struct virtio_fs_dispatch;

typedef int (*virtio_fs_dispatch_publish_cb)(void *,
	    const struct virtio_fs_backend_header *, const void *);

int	virtio_fs_dispatch_error_response(
	    const struct virtio_fs_request_context *, uint8_t[16]);
int	virtio_fs_dispatch_create(
	    const struct virtio_fs_backend_session *,
	    struct virtio_fs_dispatch **);
void	virtio_fs_dispatch_destroy(struct virtio_fs_dispatch *);
int	virtio_fs_dispatch_submit(struct virtio_fs_dispatch *,
	    enum virtio_fs_queue_class, const void *, size_t, size_t,
	    struct virtio_fs_backend_header *);
int	virtio_fs_dispatch_submit_owned(struct virtio_fs_dispatch *,
	    enum virtio_fs_queue_class, const void *, size_t, size_t,
	    uintptr_t, struct virtio_fs_backend_header *);
int	virtio_fs_dispatch_submit_publish_owned(struct virtio_fs_dispatch *,
	    enum virtio_fs_queue_class, const void *, size_t, size_t,
	    uintptr_t, virtio_fs_dispatch_publish_cb, void *,
	    struct virtio_fs_backend_header *);
int	virtio_fs_dispatch_submit_publish_owned_on(
	    struct virtio_fs_dispatch *, enum virtio_fs_queue_class,
	    const void *, size_t, size_t, uintptr_t, uint32_t,
	    virtio_fs_dispatch_publish_cb, void *,
	    struct virtio_fs_backend_header *);
int	virtio_fs_dispatch_owner(struct virtio_fs_dispatch *, uint64_t,
	    uint64_t, uintptr_t *);
int	virtio_fs_dispatch_complete(struct virtio_fs_dispatch *,
	    const struct virtio_fs_backend_header *, const void *, size_t,
	    void *, size_t, size_t *);
int	virtio_fs_dispatch_complete_owned(struct virtio_fs_dispatch *,
	    const struct virtio_fs_backend_header *, const void *, size_t,
	    void *, size_t, size_t *, uintptr_t *);
int	virtio_fs_dispatch_noreply_sent(struct virtio_fs_dispatch *,
	    uint64_t, uint64_t);
int	virtio_fs_dispatch_noreply_sent_owned(struct virtio_fs_dispatch *,
	    uint64_t, uint64_t, uintptr_t *);
int	virtio_fs_dispatch_mark_sent(struct virtio_fs_dispatch *, uint64_t,
	    uint64_t);
int	virtio_fs_dispatch_cancel(struct virtio_fs_dispatch *, uint64_t,
	    uint64_t, struct virtio_fs_backend_header *);
int	virtio_fs_dispatch_cancel_queue_publish(
	    struct virtio_fs_dispatch *, uint32_t,
	    virtio_fs_dispatch_publish_cb, void *,
	    struct virtio_fs_backend_header *, uintptr_t *);
int	virtio_fs_dispatch_cancel_complete(struct virtio_fs_dispatch *,
	    const struct virtio_fs_backend_header *, void *, size_t, size_t *);
int	virtio_fs_dispatch_cancel_complete_owned(
	    struct virtio_fs_dispatch *,
	    const struct virtio_fs_backend_header *, void *, size_t, size_t *,
	    uintptr_t *);
int	virtio_fs_dispatch_retired_frame(struct virtio_fs_dispatch *,
	    const struct virtio_fs_backend_header *, size_t);
int	virtio_fs_dispatch_abort(struct virtio_fs_dispatch *, uint64_t,
	    uint64_t, void *, size_t, size_t *);
int	virtio_fs_dispatch_pause(struct virtio_fs_dispatch *, uint32_t *);
void	virtio_fs_dispatch_resume(struct virtio_fs_dispatch *);
int	virtio_fs_dispatch_session_snapshot(struct virtio_fs_dispatch *,
	    struct virtio_fs_session *);
int	virtio_fs_dispatch_session_restore(struct virtio_fs_dispatch *,
	    const struct virtio_fs_session *);
int	virtio_fs_dispatch_reset(struct virtio_fs_dispatch *,
	    struct virtio_fs_pending_result *, size_t, size_t *);
int	virtio_fs_dispatch_reset_queue(struct virtio_fs_dispatch *, uint32_t,
	    struct virtio_fs_pending_result *, size_t, size_t *);
int	virtio_fs_dispatch_disconnect(struct virtio_fs_dispatch *,
	    struct virtio_fs_pending_result *, size_t, size_t *);
uint32_t virtio_fs_dispatch_pending(struct virtio_fs_dispatch *);

#endif
