/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_VIRTIO_DEVICE_PARTS_H_
#define	_BHYVE_VIRTIO_DEVICE_PARTS_H_

#include <sys/types.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define	BHYVE_VIRTIO_DEV_PART_F_OPTIONAL	0x01U

#define	BHYVE_VIRTIO_DEV_PART_DEV_FEATURES	0x0100U
#define	BHYVE_VIRTIO_DEV_PART_DRV_FEATURES	0x0101U
#define	BHYVE_VIRTIO_DEV_PART_PCI_COMMON_CFG	0x0102U
#define	BHYVE_VIRTIO_DEV_PART_DEVICE_STATUS	0x0103U
#define	BHYVE_VIRTIO_DEV_PART_VQ_CFG		0x0104U
#define	BHYVE_VIRTIO_DEV_PART_VQ_NOTIFY_CFG	0x0105U

#define	BHYVE_VIRTIO_DEV_PART_HEADER_SIZE	16U
#define	BHYVE_VIRTIO_DEV_PART_VQ_CFG_SIZE	32U
#define	BHYVE_VIRTIO_DEV_PART_VQ_NOTIFY_SIZE	8U

struct virtio_device_part {
	uint16_t type;
	uint8_t flags;
	uint64_t selector;
	uint32_t length;
	const uint8_t *value;
};

struct virtio_device_parts_iterator {
	const uint8_t *bytes;
	size_t length;
	size_t offset;
	uint16_t prior_type;
	uint64_t prior_selector;
	uint32_t singleton_seen;
	uint32_t known_seen;
	bool headers_only;
	bool independent_headers;
};

void	virtio_device_parts_iterator_init(
	    struct virtio_device_parts_iterator *, const void *, size_t);
void	virtio_device_part_headers_iterator_init(
	    struct virtio_device_parts_iterator *, const void *, size_t);
void	virtio_device_part_selection_iterator_init(
	    struct virtio_device_parts_iterator *, const void *, size_t);
/*
 * Return 0 with the next part, ENOENT at the exact end, or a protocol error.
 * Unknown optional parts are returned to the caller; unknown mandatory parts
 * fail with EOPNOTSUPP.
 */
int	virtio_device_parts_next(struct virtio_device_parts_iterator *,
	    struct virtio_device_part *);
int	virtio_device_part_append(void *, size_t, size_t *, uint16_t, uint8_t,
	    uint64_t, const void *, uint32_t);
int	virtio_device_part_header_append(void *, size_t, size_t *, uint16_t,
	    uint8_t, uint64_t, uint32_t);

#endif /* _BHYVE_VIRTIO_DEVICE_PARTS_H_ */
