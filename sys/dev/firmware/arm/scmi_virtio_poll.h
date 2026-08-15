/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Small, architecture-independent policy helpers for the SCMI VirtIO
 * transport's bounded non-sleeping poll path.
 */

#ifndef _DEV_FIRMWARE_ARM_SCMI_VIRTIO_POLL_H_
#define	_DEV_FIRMWARE_ARM_SCMI_VIRTIO_POLL_H_

#define	SCMI_VIRTIO_POLLING_INTERVAL_MS	2U

static inline unsigned int
scmi_virtio_poll_probes(unsigned int timeout_ms)
{

	return (timeout_ms / SCMI_VIRTIO_POLLING_INTERVAL_MS +
	    (timeout_ms % SCMI_VIRTIO_POLLING_INTERVAL_MS != 0));
}

static inline bool
scmi_virtio_poll_timed_out(unsigned int poll_done)
{

	return (poll_done == 0);
}

#endif /* _DEV_FIRMWARE_ARM_SCMI_VIRTIO_POLL_H_ */
