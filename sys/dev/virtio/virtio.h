/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2014, Bryan Venteicher <bryanv@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _VIRTIO_H_
#define _VIRTIO_H_

#include <dev/virtio/virtio_endian.h>
#include <dev/virtio/virtio_ids.h>
#include <dev/virtio/virtio_config.h>

/* VirtIO 1.4 section 2.7: maximum split virtqueue size. */
#define	VIRTIO_SPLIT_QUEUE_SIZE_MAX	32768U

/*
 * Device and queue reset have no completion interrupt.  Bus reset methods
 * can be called while a child-driver mutex is held, so transport drivers
 * must throttle their required status polling without sleeping.
 *
 * Full-device reset has no recoverable timeout in the transport API and must
 * wait for the device to relinquish its queues.  Selective queue reset does
 * return an error, so bound it to one second: long enough for an asynchronous
 * backend drain, but finite when a broken device never clears queue_reset.
 */
#define	VIRTIO_RESET_POLL_DELAY_US	1000U
#define	VIRTIO_QUEUE_RESET_TIMEOUT_US	1000000U
#define	VIRTIO_QUEUE_RESET_POLLS					\
	(VIRTIO_QUEUE_RESET_TIMEOUT_US / VIRTIO_RESET_POLL_DELAY_US)
#define	VIRTIO_QUEUE_RESET_PROBES	(VIRTIO_QUEUE_RESET_POLLS + 1U)
#if VIRTIO_QUEUE_RESET_TIMEOUT_US % VIRTIO_RESET_POLL_DELAY_US != 0
#error "VirtIO queue reset timeout must be an integral number of polls"
#endif

static inline bool
virtio_queue_reset_probe_should_delay(uint32_t probe)
{

	return (probe < VIRTIO_QUEUE_RESET_POLLS);
}

static inline bool
virtio_features_subset(uint64_t available, uint64_t requested)
{

	return ((requested & ~available) == 0);
}

static inline bool
virtio_split_queue_size_valid(uint32_t size)
{

	return (size != 0 && size <= VIRTIO_SPLIT_QUEUE_SIZE_MAX &&
	    (size & (size - 1)) == 0);
}

/* VirtIO 1.4 section 4.1.5.2 PCI notification write width. */
static inline uint8_t
virtio_pci_queue_notify_size(bool notification_data)
{

	return (notification_data ? 4 : 2);
}

/*
 * VirtIO 1.4 sections 4.1.4.3 and 4.1.5.2.  NotificationConfigData changes
 * only the low 16-bit notification identifier; it is independent of whether
 * NotificationData widens the PCI transaction and supplies ring cursor data
 * in the high 16 bits.
 */
static inline uint16_t
virtio_pci_notification_identifier(uint16_t queue,
    uint16_t queue_notif_config_data, bool notif_config_data)
{

	return (notif_config_data ? queue_notif_config_data : queue);
}

/*
 * NotificationData is implemented by the transport.  A child driver's
 * feature mask cannot override validation of the device notification window.
 */
static inline uint64_t
virtio_modern_notification_data_features(uint64_t child_features,
    uint64_t host_features, bool layout_valid)
{

	child_features &= ~VIRTIO_F_NOTIFICATION_DATA;
	if ((host_features & VIRTIO_F_NOTIFICATION_DATA) != 0 && layout_valid)
		child_features |= VIRTIO_F_NOTIFICATION_DATA;
	return (child_features);
}

/* VirtIO 1.4 sections 2.9 and 4.1.5.2, split-ring notification data. */
static inline uint32_t
virtio_split_notification_data(uint16_t notification_identifier,
    uint16_t avail_idx)
{

	return ((uint32_t)notification_identifier |
	    (uint32_t)avail_idx << 16);
}

static inline bool
virtio_config_range_valid(uint64_t size, uint64_t offset, uint64_t length)
{

	return (offset <= size && length <= size - offset);
}

/*
 * VirtIO 1.4 sections 4.1.3.1 and 4.2.2.2 require naturally aligned
 * accesses matching the field width.  A 64-bit field is transferred as two
 * aligned 32-bit accesses by the transport implementation.
 */
static inline bool
virtio_modern_config_access_valid(uint64_t size, uint64_t offset, int length)
{
	uint64_t alignment;

	switch (length) {
	case 1:
	case 2:
	case 4:
	case 8:
		break;
	default:
		return (false);
	}
	alignment = length > 4 ? 4 : length;
	return (virtio_config_range_valid(size, offset, length) &&
	    offset % alignment == 0);
}

/* Assemble and split the independently accessible halves of a 64-bit field. */
static inline uint64_t
virtio_config_read64_parts(bool modern, uint32_t low, uint32_t high)
{

	return (((uint64_t)virtio_htog32(modern, high) << 32) |
	    virtio_htog32(modern, low));
}

static inline void
virtio_config_write64_parts(bool modern, uint64_t value, uint32_t *low,
    uint32_t *high)
{

	*low = virtio_gtoh32(modern, (uint32_t)value);
	*high = virtio_gtoh32(modern, value >> 32);
}

/*
 * Keep only document-assigned device and legacy bits plus transport features
 * implemented by the common virtqueue driver.
 */
static inline uint64_t
virtio_supported_transport_features(uint64_t features)
{
	uint64_t mask;

	/*
	 * VirtIO 1.4 section 2.2 allocates device features at bits 0--23,
	 * 41--42, and 50--127.  Bits 24 and 27 are also valid on a legacy
	 * interface.  Start with only those non-common allocations so reserved
	 * bits 25--26 and 44--49 cannot pass through merely because they sit
	 * outside VIRTIO_TRANSPORT_F_MASK.
	 */
	mask = (1ULL << 24) - 1;
	mask |= VIRTIO_F_NOTIFY_ON_EMPTY;
	mask |= VIRTIO_F_ANY_LAYOUT;
	mask |= 3ULL << 41;
	mask |= ~((1ULL << 50) - 1);
	mask |= VIRTIO_RING_F_INDIRECT_DESC;
	mask |= VIRTIO_RING_F_EVENT_IDX;
	mask |= VIRTIO_F_VERSION_1;
	mask |= VIRTIO_F_RING_PACKED;
	mask |= VIRTIO_F_IN_ORDER;
	mask |= VIRTIO_F_NOTIFICATION_DATA;
	mask |= VIRTIO_F_NOTIF_CONFIG_DATA;
	mask |= VIRTIO_F_RING_RESET;
	mask |= VIRTIO_F_SUSPEND;

	return (features & mask);
}

#define	VIRTIO_PACKED_QUEUE_SIZE_MAX	32768U

static inline bool
virtio_packed_queue_size_valid(uint32_t size)
{

	return (size >= 1 && size <= VIRTIO_PACKED_QUEUE_SIZE_MAX);
}

static inline bool
virtio_queue_size_valid(bool packed, uint32_t size)
{

	return (packed ? virtio_packed_queue_size_valid(size) :
	    virtio_split_queue_size_valid(size));
}

/*
 * Bits 24 and 27 are legacy-only.  Bits 41 and 42 are device-specific only
 * for the legacy network interface; in a modern transport bit 41 is
 * VIRTIO_F_ADMIN_VQ and bit 42 is reserved.  None is implemented by the
 * common FreeBSD modern transport.
 */
static inline uint64_t
virtio_modern_supported_transport_features(uint64_t features)
{

	features = virtio_supported_transport_features(features);
	features &= ~VIRTIO_F_NOTIFY_ON_EMPTY;
	features &= ~VIRTIO_F_ANY_LAYOUT;
	features &= ~VIRTIO_F_ADMIN_VQ;
	features &= ~(1ULL << 42);
	return (features);
}

static inline bool
virtio_device_suspend_complete(uint8_t status)
{

	return ((status & (VIRTIO_CONFIG_STATUS_SUSPEND |
	    VIRTIO_CONFIG_STATUS_DRIVER_OK)) ==
	    VIRTIO_CONFIG_STATUS_SUSPEND);
}

/*
 * VirtIO 1.4 section 3.4.1 says that a driver should not request suspend
 * before DRIVER_OK.  Treat a device that already reports a terminal failure
 * as ineligible too: there is no useful lifecycle handshake to start, and
 * preserving its reset-required state is safer than adding SUSPEND to it.
 */
static inline bool
virtio_device_suspend_request_allowed(uint8_t status)
{

	return ((status & (VIRTIO_CONFIG_STATUS_DRIVER_OK |
	    VIRTIO_CONFIG_S_NEEDS_RESET | VIRTIO_CONFIG_STATUS_FAILED)) ==
	    VIRTIO_CONFIG_STATUS_DRIVER_OK);
}

static inline bool
virtio_device_resume_complete(uint8_t status)
{

	return ((status & (VIRTIO_CONFIG_STATUS_SUSPEND |
	    VIRTIO_CONFIG_STATUS_DRIVER_OK)) ==
	    VIRTIO_CONFIG_STATUS_DRIVER_OK);
}

enum virtio_device_lifecycle_state {
	VIRTIO_DEVICE_LIFECYCLE_FAILED,
	VIRTIO_DEVICE_LIFECYCLE_RUNNING,
	VIRTIO_DEVICE_LIFECYCLE_SUSPENDED,
	VIRTIO_DEVICE_LIFECYCLE_TRANSITION
};

/*
 * Classify a status sample for suspend rollback.  Failure has precedence:
 * DRIVER_OK does not make a device usable after it requested reset or after
 * the driver gave up.  The two completion predicates intentionally ignore
 * unrelated cumulative status bits.
 */
static inline enum virtio_device_lifecycle_state
virtio_device_lifecycle_state(uint8_t status)
{

	if ((status & (VIRTIO_CONFIG_S_NEEDS_RESET |
	    VIRTIO_CONFIG_STATUS_FAILED)) != 0)
		return (VIRTIO_DEVICE_LIFECYCLE_FAILED);
	if (virtio_device_resume_complete(status))
		return (VIRTIO_DEVICE_LIFECYCLE_RUNNING);
	if (virtio_device_suspend_complete(status))
		return (VIRTIO_DEVICE_LIFECYCLE_SUSPENDED);
	return (VIRTIO_DEVICE_LIFECYCLE_TRANSITION);
}

/*
 * The legacy MMIO register layout has no QueueReset register and predates
 * VERSION_1-only lifecycle features.  Filter those features before
 * negotiation so a version 1 transport cannot promise operations it has no
 * way to perform.  NotificationConfigData is also transport-specific: MMIO
 * has no register through which a device can provide its per-queue identifier
 * (VirtIO 1.4 section 2.9), so it is unsupported for every MMIO version.
 * Version 2 and later use the common modern transport and virtqueue
 * implementations, including packed rings and device suspend.
 */
static inline uint64_t
virtio_mmio_supported_transport_features(uint32_t version, uint64_t features)
{

	if (version > 1)
		features = virtio_modern_supported_transport_features(features);
	else {
		features = virtio_supported_transport_features(features);
		features &= ~VIRTIO_F_RING_RESET;
		features &= ~VIRTIO_F_SUSPEND;
	}
	features &= ~VIRTIO_F_NOTIF_CONFIG_DATA;
	return (features);
}

/*
 * Function drivers describe device-specific features.  A modern MMIO bus
 * must add the transport features implemented by the common virtqueue and
 * lifecycle layers before intersecting that request with the device offer.
 */
static inline uint64_t
virtio_mmio_requested_transport_features(uint32_t version,
    uint64_t child_features, uint64_t host_features)
{

	if (version <= 1)
		return (child_features);
	child_features |= VIRTIO_F_VERSION_1;
	/* NotificationConfigData has no MMIO delivery/register definition. */
	child_features |= host_features & (VIRTIO_F_RING_PACKED |
	    VIRTIO_F_NOTIFICATION_DATA | VIRTIO_F_SUSPEND);
	return (child_features);
}

#ifdef _KERNEL

struct sbuf;
struct vq_alloc_info;
struct virtqueue;

/*
 * Each virtqueue indirect descriptor list must be physically contiguous.
 * To allow us to malloc(9) each list individually, limit the number
 * supported to what will fit in one page. With 4KB pages, this is a limit
 * of 256 descriptors. If there is ever a need for more, we can switch to
 * contigmalloc(9) for the larger allocations, similar to what
 * bus_dmamem_alloc(9) does.
 *
 * Note the sizeof(struct vring_desc) is 16 bytes.
 */
#define VIRTIO_MAX_INDIRECT ((int) (PAGE_SIZE / 16))

/*
 * VirtIO instance variables indices.
 */
enum {
	VIRTIO_IVAR_DEVTYPE = BUS_IVARS_PRIVATE,
	VIRTIO_IVAR_FEATURE_DESC,
	VIRTIO_IVAR_VENDOR,
	VIRTIO_IVAR_DEVICE,
	VIRTIO_IVAR_SUBVENDOR,
	VIRTIO_IVAR_SUBDEVICE,
	VIRTIO_IVAR_MODERN
};

struct virtio_feature_desc {
	uint64_t	 vfd_val;
	const char	*vfd_str;
};

#define VIRTIO_DRIVER_MODULE(name, driver, evh, arg)			\
	DRIVER_MODULE(name, virtio_mmio, driver, evh, arg);		\
	DRIVER_MODULE(name, virtio_pci, driver, evh, arg)

struct virtio_pnp_match {
	uint32_t	 device_type;
	const char	*description;
};
#define VIRTIO_SIMPLE_PNPINFO(driver, devtype, desc)			\
	static const struct virtio_pnp_match driver ## _match = {	\
		.device_type = devtype,					\
		.description = desc,					\
	};								\
	MODULE_PNP_INFO("U32:device_type;D:#", virtio_mmio, driver,	\
	    &driver ## _match, 1);					\
	MODULE_PNP_INFO("U32:device_type;D:#", virtio_pci, driver,	\
	    &driver ## _match, 1)
#define VIRTIO_SIMPLE_PROBE(dev, driver)				\
	(virtio_simple_probe(dev, &driver ## _match))

const char *virtio_device_name(uint16_t devid);
void	 virtio_describe(device_t dev, const char *msg,
	     uint64_t features, struct virtio_feature_desc *desc);
int	 virtio_describe_sbuf(struct sbuf *sb, uint64_t features,
	     struct virtio_feature_desc *desc);
uint64_t virtio_filter_transport_features(uint64_t features);
bool	 virtio_bus_is_modern(device_t dev);
void	 virtio_read_device_config_array(device_t dev, bus_size_t offset,
	     void *dst, int size, int count);

/*
 * VirtIO Bus Methods.
 */
void	 virtio_read_ivar(device_t dev, int ivar, uintptr_t *val);
void	 virtio_write_ivar(device_t dev, int ivar, uintptr_t val);
uint64_t virtio_negotiate_features(device_t dev, uint64_t child_features);
int	 virtio_finalize_features(device_t dev);
int	 virtio_alloc_virtqueues(device_t dev, int nvqs,
	     struct vq_alloc_info *info);
int	 virtio_setup_intr(device_t dev, enum intr_type type);
void	 virtio_teardown_intr(device_t dev);
bool	 virtio_with_feature(device_t dev, uint64_t feature);
void	 virtio_stop(device_t dev);
int	 virtio_config_generation(device_t dev);
int	 virtio_reinit(device_t dev, uint64_t features);
void	 virtio_reinit_complete(device_t dev);
/*
 * The child driver must quiesce the queue before resetting it.  A successful
 * reset leaves the queue disabled; it must be configured again before reuse.
 */
int	 virtio_reset_virtqueue(device_t dev, struct virtqueue *vq);
int	 virtio_child_pnpinfo(device_t busdev, device_t child, struct sbuf *sb);

/*
 * Read/write a variable amount from the device-specific (for example,
 * network) configuration region.  Legacy transports use guest-native byte
 * order; modern transports convert the little-endian wire fields to and from
 * guest-native values before invoking these interfaces.
 */
void	 virtio_read_device_config(device_t dev, bus_size_t offset,
	     void *dst, int length);
void	 virtio_write_device_config(device_t dev, bus_size_t offset,
	     const void *src, int length);

/* Inlined device specific read/write functions for common lengths. */
#define VIRTIO_RDWR_DEVICE_CONFIG(size, type)				\
static inline type							\
__CONCAT(virtio_read_dev_config_,size)(device_t dev,			\
    bus_size_t offset)							\
{									\
	type val;							\
	virtio_read_device_config(dev, offset, &val, sizeof(type));	\
	return (val);							\
}									\
									\
static inline void							\
__CONCAT(virtio_write_dev_config_,size)(device_t dev,			\
    bus_size_t offset, type val)					\
{									\
	virtio_write_device_config(dev, offset, &val, sizeof(type));	\
}

VIRTIO_RDWR_DEVICE_CONFIG(1, uint8_t);
VIRTIO_RDWR_DEVICE_CONFIG(2, uint16_t);
VIRTIO_RDWR_DEVICE_CONFIG(4, uint32_t);

#undef VIRTIO_RDWR_DEVICE_CONFIG

#define VIRTIO_READ_IVAR(name, ivar)					\
static inline int							\
__CONCAT(virtio_get_,name)(device_t dev)				\
{									\
	uintptr_t val;							\
	virtio_read_ivar(dev, ivar, &val);				\
	return ((int) val);						\
}

VIRTIO_READ_IVAR(device_type,	VIRTIO_IVAR_DEVTYPE);
VIRTIO_READ_IVAR(vendor,	VIRTIO_IVAR_VENDOR);
VIRTIO_READ_IVAR(device,	VIRTIO_IVAR_DEVICE);
VIRTIO_READ_IVAR(subvendor,	VIRTIO_IVAR_SUBVENDOR);
VIRTIO_READ_IVAR(subdevice,	VIRTIO_IVAR_SUBDEVICE);
VIRTIO_READ_IVAR(modern,	VIRTIO_IVAR_MODERN);

#undef VIRTIO_READ_IVAR

#define VIRTIO_WRITE_IVAR(name, ivar)					\
static inline void							\
__CONCAT(virtio_set_,name)(device_t dev, void *val)			\
{									\
	virtio_write_ivar(dev, ivar, (uintptr_t) val);			\
}

VIRTIO_WRITE_IVAR(feature_desc,	VIRTIO_IVAR_FEATURE_DESC);

#undef VIRTIO_WRITE_IVAR

static inline int
virtio_simple_probe(device_t dev, const struct virtio_pnp_match *match)
{

	if (virtio_get_device_type(dev) != match->device_type)
		return (ENXIO);
	device_set_desc(dev, match->description);
	return (BUS_PROBE_DEFAULT);
}

#endif /* _KERNEL */

#endif /* _VIRTIO_H_ */
