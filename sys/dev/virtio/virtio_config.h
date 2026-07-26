/*-
 * This header is BSD licensed so anyone can use the definitions to implement
 * compatible drivers/servers.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of IBM nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL IBM OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _VIRTIO_CONFIG_H_
#define _VIRTIO_CONFIG_H_

/* Status byte for guest to report progress. */
#define VIRTIO_CONFIG_STATUS_RESET	0x00
/* We have seen device and processed generic fields. */
#define VIRTIO_CONFIG_STATUS_ACK	0x01
/* We have found a driver for the device. */
#define VIRTIO_CONFIG_STATUS_DRIVER	0x02
/* Driver has used its parts of the config, and is happy. */
#define VIRTIO_CONFIG_STATUS_DRIVER_OK	0x04
/* Driver has finished configuring features (modern only). */
#define VIRTIO_CONFIG_S_FEATURES_OK	0x08
/* Device is quiesced after VIRTIO_F_SUSPEND negotiation. */
#define VIRTIO_CONFIG_STATUS_SUSPEND	0x10
/* Device entered invalid state, driver must reset it. */
#define VIRTIO_CONFIG_S_NEEDS_RESET	0x40
/* We've given up on this device. */
#define VIRTIO_CONFIG_STATUS_FAILED	0x80

/*
 * Generate interrupt when the virtqueue ring is
 * completely used, even if we've suppressed them.
 */
#define VIRTIO_F_NOTIFY_ON_EMPTY	(1UL << 24)

/* Can the device handle any descriptor layout? */
#define VIRTIO_F_ANY_LAYOUT		(1UL << 27)

/* Support for indirect buffer descriptors. */
#define VIRTIO_RING_F_INDIRECT_DESC	(1UL << 28)

/* Support to suppress interrupt until specific index is reached. */
#define VIRTIO_RING_F_EVENT_IDX		(1UL << 29)

/*
 * The guest should never negotiate this feature; it
 * is used to detect faulty drivers.
 */
#define VIRTIO_F_BAD_FEATURE	(1UL << 30)

/* v1.0 compliant. */
#define VIRTIO_F_VERSION_1	(1ULL << 32)

/*
 * If clear - device has the IOMMU bypass quirk feature.
 * If set - use platform tools to detect the IOMMU.
 *
 * Note the reverse polarity (compared to most other features),
 * this is for compatibility with legacy systems.
 */
#define VIRTIO_F_IOMMU_PLATFORM		(1ULL << 33)
#define VIRTIO_F_ACCESS_PLATFORM	VIRTIO_F_IOMMU_PLATFORM

/*
 * The device uses packed virtqueues.
 */
#define VIRTIO_F_RING_PACKED		(1ULL << 34)

/* The device uses buffers in the order in which they become available. */
#define VIRTIO_F_IN_ORDER		(1ULL << 35)

/* Memory accesses by the device are ordered as seen by the driver. */
#define VIRTIO_F_ORDER_PLATFORM		(1ULL << 36)

/* The device supports Single Root I/O Virtualization. */
#define VIRTIO_F_SR_IOV			(1ULL << 37)

/* Driver notifications carry the available index or wrap counter. */
#define VIRTIO_F_NOTIFICATION_DATA	(1ULL << 38)

/* The PCI common configuration provides per-queue notification data. */
#define VIRTIO_F_NOTIF_CONFIG_DATA	(1ULL << 39)

/* The driver can reset individual virtqueues. */
#define VIRTIO_F_RING_RESET		(1ULL << 40)

/* The device exposes one or more administration virtqueues. */
#define VIRTIO_F_ADMIN_VQ		(1ULL << 41)

/* The driver can suspend the device through the status field. */
#define VIRTIO_F_SUSPEND		(1ULL << 43)

/*
 * VirtIO 1.4 reserves the contiguous range 28 through 40 for transport,
 * virtqueue, and feature-negotiation mechanisms.  Bit 41 is
 * VIRTIO_F_ADMIN_VQ for modern owner devices, while bits 41 and 42 are also
 * assigned by section 5.1.3.2 only to the legacy network interface; leave
 * both to the transport/device-specific negotiation path.  Bit 43 is the
 * non-contiguous VIRTIO_F_SUSPEND common feature.
 * VIRTIO_TRANSPORT_F_END is exclusive.
 */
#define VIRTIO_TRANSPORT_F_START	28
#define VIRTIO_TRANSPORT_F_END		41
#define VIRTIO_TRANSPORT_F_MASK					\
	(((((1ULL << (VIRTIO_TRANSPORT_F_END -			\
	    VIRTIO_TRANSPORT_F_START)) - 1) <<			\
	    VIRTIO_TRANSPORT_F_START)) | VIRTIO_F_SUSPEND)

#endif /* _VIRTIO_CONFIG_H_ */
