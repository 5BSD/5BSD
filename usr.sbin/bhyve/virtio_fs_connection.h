/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_VIRTIO_FS_CONNECTION_H_
#define	_BHYVE_VIRTIO_FS_CONNECTION_H_

#include <sys/types.h>
#include <sys/uio.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "virtio_fs_backend.h"
#include "virtio_fs_host.h"
#include "virtio_fs_queue.h"

#define	VIRTIO_FS_CONNECTION_READ	(UINT32_C(1) << 0)
#define	VIRTIO_FS_CONNECTION_WRITE	(UINT32_C(1) << 1)

struct virtio_fs_connection;

/*
 * Invoked with the connection serializer held.  EAGAIN retains one received
 * notification for retry when the guest later posts a notification buffer.
 */
typedef int (*virtio_fs_connection_notify_cb)(void *, const void *, size_t);

/*
 * The caller serializes concurrent public operations and excludes destroy()
 * from every public call that can touch the connection, including progress,
 * queue submission, and readiness queries.  adopt() takes ownership of fd
 * only on success.  A synchronous completion callback may submit more work
 * on the same serialized path, but must not destroy the connection.
 */
int	virtio_fs_connection_connect(const char *, uid_t, gid_t,
	    const struct virtio_fs_backend_hello *, uint32_t, uint32_t,
	    virtio_fs_queue_complete_cb, void *,
	    struct virtio_fs_connection **);
int	virtio_fs_connection_connect_required(const char *, uid_t, gid_t,
	    const struct virtio_fs_backend_hello *, uint32_t, uint32_t,
	    uint32_t, virtio_fs_queue_complete_cb, void *,
	    struct virtio_fs_connection **);
int	virtio_fs_connection_adopt(int, uid_t, gid_t,
	    const struct virtio_fs_backend_hello *, uint32_t, uint32_t,
	    virtio_fs_queue_complete_cb, void *,
	    struct virtio_fs_connection **);
int	virtio_fs_connection_adopt_required(int, uid_t, gid_t,
	    const struct virtio_fs_backend_hello *, uint32_t, uint32_t,
	    uint32_t, virtio_fs_queue_complete_cb, void *,
	    struct virtio_fs_connection **);
void	virtio_fs_connection_destroy(struct virtio_fs_connection *);
int	virtio_fs_connection_set_reset_complete(
	    struct virtio_fs_connection *,
	    virtio_fs_queue_reset_complete_cb, void *);
int	virtio_fs_connection_set_discard(
	    struct virtio_fs_connection *, virtio_fs_queue_discard_cb,
	    void *);
int	virtio_fs_connection_set_notification(struct virtio_fs_connection *,
	    virtio_fs_connection_notify_cb, void *);
int	virtio_fs_connection_retry_notification(struct virtio_fs_connection *);
int	virtio_fs_connection_fd(const struct virtio_fs_connection *);
uint32_t virtio_fs_connection_events(struct virtio_fs_connection *);
int	virtio_fs_connection_progress(struct virtio_fs_connection *,
	    bool, bool);
bool	virtio_fs_connection_active(
	    const struct virtio_fs_connection *);
int	virtio_fs_connection_error(
	    const struct virtio_fs_connection *);
int	virtio_fs_connection_submit(struct virtio_fs_connection *,
	    enum virtio_fs_queue_class, const struct iovec *, size_t, size_t,
	    size_t, bool, uintptr_t);
int	virtio_fs_connection_submit_on(struct virtio_fs_connection *,
	    uint32_t, enum virtio_fs_queue_class, const struct iovec *, size_t,
	    size_t, size_t, bool, uintptr_t);
int	virtio_fs_connection_reset_queue(struct virtio_fs_connection *,
	    uint32_t, size_t *);
int	virtio_fs_connection_reset(struct virtio_fs_connection *, size_t *);
uint32_t virtio_fs_connection_pending(struct virtio_fs_connection *);
uint32_t virtio_fs_connection_outgoing(struct virtio_fs_connection *);
/*
 * Return the immutable backend compatibility contract used by restore
 * preflight.  This does not close admission, emit a control frame, or alter
 * the live connection.  The returned phase is normalized to QUIESCED because
 * a checkpoint image is necessarily captured in that phase.
 */
int	virtio_fs_connection_checkpoint_contract(
	    const struct virtio_fs_connection *,
	    struct virtio_fs_backend_session *);
/*
 * pause() closes guest-request admission and succeeds only after no queue
 * ownership or unsent frame remains.  On failure it reopens admission, since
 * the bhyve checkpoint coordinator will not call resume() after a failed
 * device pause.  A successful caller must eventually call resume().
 */
int	virtio_fs_connection_pause(struct virtio_fs_connection *,
	    struct virtio_fs_session *, struct virtio_fs_backend_session *);
void	virtio_fs_connection_resume(struct virtio_fs_connection *);
int	virtio_fs_connection_restore_session(
	    struct virtio_fs_connection *, const struct virtio_fs_session *);
/*
 * Backend freeze/thaw is asynchronous: begin_quiesce() first returns
 * EINPROGRESS while already-accepted requests drain with admission closed,
 * then queues exactly one control frame when retried.  progress() advances
 * socket I/O, and control_status() reports EINPROGRESS until the matching
 * reply arrives.
 * A successful quiesce retains an opaque backend blob for checkpointing.
 */
int	virtio_fs_connection_begin_quiesce(struct virtio_fs_connection *);
int	virtio_fs_connection_begin_thaw(struct virtio_fs_connection *,
	    const void *, size_t);
int	virtio_fs_connection_begin_thaw_saved(
	    struct virtio_fs_connection *);
int	virtio_fs_connection_control_status(
	    const struct virtio_fs_connection *);
size_t	virtio_fs_connection_checkpoint_size(
	    const struct virtio_fs_connection *);
int	virtio_fs_connection_checkpoint_copy(
	    const struct virtio_fs_connection *, struct virtio_fs_session *,
	    struct virtio_fs_backend_session *, void *, size_t, size_t *);
int	virtio_fs_connection_abort_control(struct virtio_fs_connection *, int);

#endif
