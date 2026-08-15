/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_VIRTIO_SND_ASYNC_H_
#define	_BHYVE_VIRTIO_SND_ASYNC_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/uio.h>

#define	BHYVE_VTSND_ASYNC_STREAMS	2U

enum virtio_snd_async_direction {
	BHYVE_VTSND_ASYNC_PLAYBACK = 0,
	BHYVE_VTSND_ASYNC_CAPTURE = 1,
};

enum virtio_snd_async_status {
	BHYVE_VTSND_ASYNC_OK = 0,
	BHYVE_VTSND_ASYNC_IO_ERR = 1,
};

/*
 * progress() performs at most one nonblocking backend operation.  It returns
 * zero with positive progress, EAGAIN with zero progress, or another errno.
 * Both callbacks execute without the async-owner mutex held.  During
 * progress(), the job is pinned, so cancellation, lifecycle quiesce, and
 * destruction return EBUSY rather than racing callback-owned storage.
 * complete() receives capture bytes only on a successful capture completion.
 */
struct virtio_snd_async_ops {
	int	(*progress)(void *, enum virtio_snd_async_direction, void *,
		    size_t, size_t *);
	void	(*complete)(void *, uintptr_t, enum virtio_snd_async_status,
		    const void *, size_t);
	void	*arg;
};

struct virtio_snd_async;

int	virtio_snd_async_create(const struct virtio_snd_async_ops *, size_t,
	    struct virtio_snd_async **);
/*
 * Destruction is deliberately fail-closed: the caller must first complete or
 * cancel every job and exclude concurrent API calls.  EBUSY leaves the owner
 * intact, including its callbacks and buffers.
 */
int	virtio_snd_async_destroy(struct virtio_snd_async *);
int	virtio_snd_async_submit(struct virtio_snd_async *, uint32_t,
	    enum virtio_snd_async_direction, uintptr_t, uint64_t,
	    const void *, size_t);
int	virtio_snd_async_submit_iov(struct virtio_snd_async *, uint32_t,
	    enum virtio_snd_async_direction, uintptr_t, uint64_t,
	    const struct iovec *, size_t, size_t, size_t);
int	virtio_snd_async_progress(struct virtio_snd_async *, uint32_t,
	    uint64_t);
int	virtio_snd_async_cancel(struct virtio_snd_async *, uint32_t,
	    uint64_t);
int	virtio_snd_async_pending(struct virtio_snd_async *, uint32_t,
	    bool *, size_t *);
/*
 * Quiesce closes new job admission only after observing that all existing
 * jobs and completions have drained.  resume() reopens admission only while
 * that same empty condition still holds, so a lifecycle caller cannot turn a
 * failed quiesce into a new retained DMA owner.
 */
int	virtio_snd_async_quiesce(struct virtio_snd_async *);
int	virtio_snd_async_resume(struct virtio_snd_async *);

#endif /* _BHYVE_VIRTIO_SND_ASYNC_H_ */
