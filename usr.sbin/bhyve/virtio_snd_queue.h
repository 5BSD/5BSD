/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_VIRTIO_SND_QUEUE_H_
#define	_BHYVE_VIRTIO_SND_QUEUE_H_

#include <sys/uio.h>

#include <stddef.h>
#include <stdint.h>

struct virtio_snd_host;
struct virtio_snd_host_xfer_claim;

#define	BHYVE_VTSND_MAX_CHAIN_SEGMENTS	256U

int	virtio_snd_queue_control(struct virtio_snd_host *,
	    const struct iovec *, size_t, const struct iovec *, size_t, size_t *);
int	virtio_snd_queue_playback(struct virtio_snd_host *,
	    const struct iovec *, size_t, const struct iovec *, size_t, size_t *);
int	virtio_snd_queue_capture(struct virtio_snd_host *,
	    const struct iovec *, size_t, const struct iovec *, size_t, size_t *);
int	virtio_snd_queue_playback_prepare(struct virtio_snd_host *,
	    const struct iovec *, size_t, const struct iovec *, size_t,
	    struct virtio_snd_host_xfer_claim *, size_t *);
int	virtio_snd_queue_capture_prepare(struct virtio_snd_host *,
	    const struct iovec *, size_t, const struct iovec *, size_t,
	    struct virtio_snd_host_xfer_claim *, size_t *);
int	virtio_snd_queue_playback_complete(const struct iovec *, size_t,
	    int, size_t *);
int	virtio_snd_queue_capture_complete(const struct iovec *, size_t,
	    const void *, size_t, int, size_t *);
int	virtio_snd_queue_control_header(const struct iovec *, size_t,
	    uint32_t *, uint32_t *);
int	virtio_snd_queue_playback_error(const struct iovec *, size_t,
	    const struct iovec *, size_t, size_t *);
int	virtio_snd_queue_capture_error(const struct iovec *, size_t,
	    const struct iovec *, size_t, size_t *);

#endif
