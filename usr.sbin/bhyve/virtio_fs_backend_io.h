/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_VIRTIO_FS_BACKEND_IO_H_
#define	_BHYVE_VIRTIO_FS_BACKEND_IO_H_

#include <sys/types.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "virtio_fs_backend.h"

/*
 * Nonblocking framing state for one backend socket.  local(4)
 * SOCK_SEQPACKET may move a record in pieces.  A frame is committed once any
 * part of it is queued: its unsent tail is copied here and must drain before
 * the next frame.  A partly received frame is reassembled here across
 * readiness callbacks.  Each piece moved renews the progress deadline of
 * its direction.
 */
struct virtio_fs_backend_stream {
	uint8_t		*send_tail;
	size_t		send_done;
	size_t		send_len;
	struct timespec	send_deadline;
	struct virtio_fs_backend_header receive_header;
	uint8_t		receive_wire[VIRTIO_FS_BACKEND_HEADER_SIZE];
	size_t		receive_done;
	size_t		receive_total;
	struct timespec	receive_deadline;
};

/*
 * A value of (uid_t)-1 or (gid_t)-1 disables that credential comparison.
 * The socket must be a connected local SOCK_SEQPACKET endpoint.
 */
int	virtio_fs_backend_connect_start(const char *, uid_t, gid_t, int *,
	    bool *);
int	virtio_fs_backend_connect_finish(int, uid_t, gid_t);
int	virtio_fs_backend_authenticate(int, uid_t, gid_t);
void	virtio_fs_backend_size_buffers(int, uint32_t);

/*
 * The stream functions never wait.  send() returns EAGAIN without taking the
 * frame while an earlier tail is unsent or the socket is full; flush() and
 * receive() return EAGAIN while a frame is incomplete.  ETIMEDOUT reports a
 * frame that could not move at all after its progress deadline: a callback
 * that runs late but finds the peer ready is not a timeout.
 */
void	virtio_fs_backend_stream_init(struct virtio_fs_backend_stream *);
void	virtio_fs_backend_stream_fini(struct virtio_fs_backend_stream *);
int	virtio_fs_backend_stream_send(struct virtio_fs_backend_stream *, int,
	    const struct virtio_fs_backend_header *, const void *);
int	virtio_fs_backend_stream_flush(struct virtio_fs_backend_stream *, int);
int	virtio_fs_backend_stream_receive(struct virtio_fs_backend_stream *,
	    int, struct virtio_fs_backend_header *, void *, size_t, size_t *);
bool	virtio_fs_backend_stream_sending(
	    const struct virtio_fs_backend_stream *);
bool	virtio_fs_backend_stream_receiving(
	    const struct virtio_fs_backend_stream *);
bool	virtio_fs_backend_stream_deadline(
	    const struct virtio_fs_backend_stream *, struct timespec *);

/*
 * Waiting helpers for the backend daemon and tests: they wait in poll(2)
 * for the rest of a frame that has started to move.  drain() finishes the
 * tail of a frame that send() has committed.
 */
int	virtio_fs_backend_stream_drain(struct virtio_fs_backend_stream *, int);
int	virtio_fs_backend_send_frame(int,
	    const struct virtio_fs_backend_header *, const void *);
int	virtio_fs_backend_receive_frame(int,
	    struct virtio_fs_backend_header *, void *, size_t, size_t *);

#endif
