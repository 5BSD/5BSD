/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * VirtIO sound (virtio-snd) guest driver -- wire protocol definitions.
 *
 * These constants describe the guest-visible contract of the virtio sound
 * device as offered by the in-tree bhyve backend (usr.sbin/bhyve:
 * pci_virtio_snd.c, virtio_snd_host.c, virtio_snd_queue.c).  They were derived
 * from that device's request/response layout and the VIRTIO specification,
 * not from any GPL implementation.
 */

#ifndef _DEV_VIRTIO_SOUND_VIRTIO_SND_H_
#define	_DEV_VIRTIO_SOUND_VIRTIO_SND_H_

/*
 * Device ID.  Defined in sys/dev/virtio/virtio_ids.h as VIRTIO_ID_SOUND (25).
 * A local fallback keeps this driver buildable even if the shared header lags;
 * the value is fixed by the VIRTIO specification.
 */
#ifndef VIRTIO_ID_SOUND
#define	VIRTIO_ID_SOUND			25
#endif

/*
 * Virtqueue indices.  The device exposes exactly four queues in this order,
 * matching the bhyve backend (VTSND_CONTROLQ .. VTSND_RXQ).
 */
#define	VTSND_VQ_CONTROL		0
#define	VTSND_VQ_EVENT			1
#define	VTSND_VQ_TX			2	/* guest -> host (playback)   */
#define	VTSND_VQ_RX			3	/* host -> guest (capture)    */
#define	VTSND_VQ_MAX			4

/*
 * Device configuration space layout (little-endian on the wire; the modern
 * transport converts to host order for virtio_read_dev_config_4()).
 */
#define	VTSND_CFG_JACKS			0	/* uint32_t */
#define	VTSND_CFG_STREAMS		4	/* uint32_t */
#define	VTSND_CFG_CHMAPS		8	/* uint32_t */
#define	VTSND_CFG_CONTROLS		12	/* uint32_t */
#define	VTSND_CFG_SIZE			16

/* Control request codes (struct virtio_snd_hdr::code). */
#define	VIRTIO_SND_R_JACK_INFO		0x0001
#define	VIRTIO_SND_R_JACK_REMAP		0x0002
#define	VIRTIO_SND_R_PCM_INFO		0x0100
#define	VIRTIO_SND_R_PCM_SET_PARAMS	0x0101
#define	VIRTIO_SND_R_PCM_PREPARE	0x0102
#define	VIRTIO_SND_R_PCM_RELEASE	0x0103
#define	VIRTIO_SND_R_PCM_START		0x0104
#define	VIRTIO_SND_R_PCM_STOP		0x0105
#define	VIRTIO_SND_R_CHMAP_INFO		0x0200

/* Event notification codes (struct virtio_snd_event::hdr). */
#define	VIRTIO_SND_EVT_JACK_CONNECTED	0x1000
#define	VIRTIO_SND_EVT_JACK_DISCONNECTED 0x1001
#define	VIRTIO_SND_EVT_PCM_PERIOD_ELAPSED 0x1100
#define	VIRTIO_SND_EVT_PCM_XRUN		0x1101

/* Common status codes (struct virtio_snd_hdr / pcm_status::status). */
#define	VIRTIO_SND_S_OK			0x8000
#define	VIRTIO_SND_S_BAD_MSG		0x8001
#define	VIRTIO_SND_S_NOT_SUPP		0x8002
#define	VIRTIO_SND_S_IO_ERR		0x8003

/* Stream direction (struct virtio_snd_pcm_info::direction). */
#define	VIRTIO_SND_D_OUTPUT		0
#define	VIRTIO_SND_D_INPUT		1

/*
 * PCM sample format identifiers (bit index within pcm_info::formats and the
 * value carried in set_params::format).  This driver only speaks S16.
 */
#define	VIRTIO_SND_PCM_FMT_S16		5

/*
 * PCM rate identifiers (bit index within pcm_info::rates and the value carried
 * in set_params::rate).
 */
#define	VIRTIO_SND_PCM_RATE_44100	6
#define	VIRTIO_SND_PCM_RATE_48000	7

/*
 * On-wire structure sizes.  The driver marshals fields explicitly with the
 * little-endian helpers rather than relying on struct layout, but the sizes
 * are used to bound the DMA staging buffers.
 */
#define	VTSND_HDR_SIZE			4	/* virtio_snd_hdr           */
#define	VTSND_PCM_HDR_SIZE		8	/* virtio_snd_pcm_hdr       */
#define	VTSND_QUERY_INFO_SIZE		16	/* virtio_snd_query_info    */
#define	VTSND_PCM_INFO_SIZE		32	/* virtio_snd_pcm_info      */
#define	VTSND_PCM_SET_PARAMS_SIZE	24	/* virtio_snd_pcm_set_params*/
#define	VTSND_PCM_XFER_SIZE		4	/* virtio_snd_pcm_xfer      */
#define	VTSND_PCM_STATUS_SIZE		8	/* virtio_snd_pcm_status    */
#define	VTSND_EVENT_SIZE		8	/* virtio_snd_event         */

#endif /* _DEV_VIRTIO_SOUND_VIRTIO_SND_H_ */
