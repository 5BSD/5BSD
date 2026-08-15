/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_VIRTIO_SND_HOST_H_
#define	_BHYVE_VIRTIO_SND_HOST_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define	BHYVE_VTSND_STREAMS		2U
#define	BHYVE_VTSND_CONFIG_SIZE		16U
#define	BHYVE_VTSND_QUERY_SIZE		16U
#define	BHYVE_VTSND_PCM_INFO_SIZE	32U
#define	BHYVE_VTSND_PCM_HEADER_SIZE	8U
#define	BHYVE_VTSND_PCM_PARAMS_SIZE	24U
#define	BHYVE_VTSND_PCM_XFER_SIZE	4U
#define	BHYVE_VTSND_STATUS_SIZE		4U
#define	BHYVE_VTSND_PCM_STATUS_SIZE	8U
#define	BHYVE_VTSND_STATE_SIZE		64U
#define	BHYVE_VTSND_MAX_BUFFER_BYTES	(16U * 1024U * 1024U)
#define	BHYVE_VTSND_R_PCM_RELEASE	0x0103U
#define	BHYVE_VTSND_S_OK		0x8000U
#define	BHYVE_VTSND_S_IO_ERR		0x8003U
#define	BHYVE_VTSND_FMT_S16		5U
#define	BHYVE_VTSND_RATE_44100		6U
#define	BHYVE_VTSND_RATE_48000		7U

enum virtio_snd_host_direction {
	BHYVE_VTSND_OUTPUT = 0,
	BHYVE_VTSND_INPUT = 1,
};

enum virtio_snd_host_stream_state {
	BHYVE_VTSND_RELEASED = 0,
	BHYVE_VTSND_PARAMS,
	BHYVE_VTSND_PREPARED,
	BHYVE_VTSND_RUNNING,
	BHYVE_VTSND_STOPPED,
};

struct virtio_snd_host_params {
	uint32_t buffer_bytes;
	uint32_t period_bytes;
	uint32_t features;
	uint8_t channels;
	uint8_t format;
	uint8_t rate;
};

struct virtio_snd_host_ops {
	int (*set_params)(void *, uint32_t,
	    const struct virtio_snd_host_params *);
	int (*prepare)(void *, uint32_t);
	int (*start)(void *, uint32_t);
	int (*stop)(void *, uint32_t);
	int (*release)(void *, uint32_t);
	int (*playback)(void *, uint32_t, const void *, size_t);
	int (*capture)(void *, uint32_t, void *, size_t);
	void *arg;
};

struct virtio_snd_host;

/*
 * The caller must stop admitting new public operations before handing
 * ownership to virtio_snd_host_destroy().  Destruction serializes with a
 * backend callback already selected by an admitted operation.  A backend
 * callback must not destroy its own host: it runs under the operation
 * serialization that destruction drains.
 */

/*
 * Runtime-only ownership returned for an admitted asynchronous PCM transfer.
 * The generation prevents a completion from an earlier queue lifetime from
 * releasing a newer transfer on the same stream.  It is deliberately absent
 * from the portable sound state: a checkpoint is rejected until every claim
 * has been finished or cancelled by the transport.
 */
struct virtio_snd_host_xfer_claim {
	uint64_t generation;
	uint32_t stream_id;
	enum virtio_snd_host_direction direction;
};

int	virtio_snd_host_create(const struct virtio_snd_host_ops *,
	    struct virtio_snd_host **);
void	virtio_snd_host_destroy(struct virtio_snd_host *);
int	virtio_snd_host_config_encode(uint8_t[BHYVE_VTSND_CONFIG_SIZE]);
int	virtio_snd_host_control(struct virtio_snd_host *, const void *, size_t,
	    void *, size_t, size_t *);
int	virtio_snd_host_playback(struct virtio_snd_host *, const void *, size_t,
	    const void *, size_t, void *, size_t, size_t *);
int	virtio_snd_host_capture(struct virtio_snd_host *, const void *, size_t,
	    void *, size_t, void *, size_t, size_t *);
int	virtio_snd_host_xfer_claim(struct virtio_snd_host *, const void *,
	    size_t, enum virtio_snd_host_direction, size_t,
	    struct virtio_snd_host_xfer_claim *);
int	virtio_snd_host_xfer_finish(struct virtio_snd_host *,
	    struct virtio_snd_host_xfer_claim *);
int	virtio_snd_host_stream_get(struct virtio_snd_host *, uint32_t,
	    enum virtio_snd_host_stream_state *, struct virtio_snd_host_params *);
int	virtio_snd_host_reset(struct virtio_snd_host *);
int	virtio_snd_host_state_encode(struct virtio_snd_host *, void *, size_t);
int	virtio_snd_host_state_validate(const void *, size_t);
int	virtio_snd_host_state_restore(struct virtio_snd_host *, const void *,
	    size_t);
bool	virtio_snd_host_restore_incomplete(struct virtio_snd_host *);
bool	virtio_snd_host_storage_overlaps(struct virtio_snd_host *,
	    const void *, size_t);

#endif
