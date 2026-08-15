/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/endian.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "virtio_device_parts.h"
#include "virtio_state_range.h"

static bool
vdev_part_known(uint16_t type)
{

	return (type >= BHYVE_VIRTIO_DEV_PART_DEV_FEATURES &&
	    type <= BHYVE_VIRTIO_DEV_PART_VQ_NOTIFY_CFG);
}

static bool
vdev_part_selector_valid(uint16_t type, const uint8_t *selector)
{

	switch (type) {
	case BHYVE_VIRTIO_DEV_PART_PCI_COMMON_CFG:
		return (le32dec(selector + 4) == 0);
	case BHYVE_VIRTIO_DEV_PART_VQ_CFG:
	case BHYVE_VIRTIO_DEV_PART_VQ_NOTIFY_CFG:
		for (size_t i = sizeof(uint16_t); i < sizeof(uint64_t); i++) {
			if (selector[i] != 0)
				return (false);
		}
		return (true);
	default:
		return (le64dec(selector) == 0);
	}
}

static bool
vdev_pci_common_cfg_field_size(uint32_t offset, uint32_t *field_size)
{

	switch (offset) {
	case 0:		/* device_feature_select */
	case 4:		/* device_feature */
	case 8:		/* driver_feature_select */
	case 12:	/* driver_feature */
	case 32:	/* queue_desc_lo */
	case 36:	/* queue_desc_hi */
	case 40:	/* queue_driver_lo */
	case 44:	/* queue_driver_hi */
	case 48:	/* queue_device_lo */
	case 52:	/* queue_device_hi */
		*field_size = sizeof(uint32_t);
		return (true);
	case 16:	/* config_msix_vector */
	case 18:	/* num_queues */
	case 22:	/* queue_select */
	case 24:	/* queue_size */
	case 26:	/* queue_msix_vector */
	case 28:	/* queue_enable */
	case 30:	/* queue_notify_off */
	case 56:	/* queue_notify_data */
	case 58:	/* queue_reset */
	case 60:	/* admin_queue_index */
	case 62:	/* admin_queue_num */
		*field_size = sizeof(uint16_t);
		return (true);
	case 20:	/* device_status */
	case 21:	/* config_generation */
		*field_size = sizeof(uint8_t);
		return (true);
	default:
		return (false);
	}
}

static bool
vdev_part_length_valid(uint16_t type, const uint8_t *selector,
    uint32_t length)
{
	uint32_t field_size;

	switch (type) {
	case BHYVE_VIRTIO_DEV_PART_DEV_FEATURES:
	case BHYVE_VIRTIO_DEV_PART_DRV_FEATURES:
		return (length != 0 && length % sizeof(uint64_t) == 0);
	case BHYVE_VIRTIO_DEV_PART_PCI_COMMON_CFG:
		return (vdev_pci_common_cfg_field_size(le32dec(selector),
		    &field_size) && length == field_size);
	case BHYVE_VIRTIO_DEV_PART_DEVICE_STATUS:
		return (length == 1);
	case BHYVE_VIRTIO_DEV_PART_VQ_CFG:
		return (length == BHYVE_VIRTIO_DEV_PART_VQ_CFG_SIZE);
	case BHYVE_VIRTIO_DEV_PART_VQ_NOTIFY_CFG:
		return (length == BHYVE_VIRTIO_DEV_PART_VQ_NOTIFY_SIZE);
	default:
		return (true);
	}
}

static uint32_t
vdev_part_singleton_bit(uint16_t type)
{

	switch (type) {
	case BHYVE_VIRTIO_DEV_PART_DEV_FEATURES:
		return (UINT32_C(1) << 0);
	case BHYVE_VIRTIO_DEV_PART_DRV_FEATURES:
		return (UINT32_C(1) << 1);
	case BHYVE_VIRTIO_DEV_PART_DEVICE_STATUS:
		return (UINT32_C(1) << 2);
	default:
		return (0);
	}
}

static uint32_t
vdev_part_known_bit(uint16_t type)
{

	if (!vdev_part_known(type))
		return (0);
	return (UINT32_C(1) <<
	    (type - BHYVE_VIRTIO_DEV_PART_DEV_FEATURES));
}

static uint32_t
vdev_part_required(uint16_t type)
{
	const uint32_t dev = UINT32_C(1) << 0;
	const uint32_t drv = UINT32_C(1) << 1;
	const uint32_t common = UINT32_C(1) << 2;
	const uint32_t status = UINT32_C(1) << 3;
	const uint32_t vq = UINT32_C(1) << 4;

	switch (type) {
	case BHYVE_VIRTIO_DEV_PART_DEV_FEATURES:
		return (0);
	case BHYVE_VIRTIO_DEV_PART_DRV_FEATURES:
		return (dev);
	case BHYVE_VIRTIO_DEV_PART_PCI_COMMON_CFG:
		return (dev | drv);
	case BHYVE_VIRTIO_DEV_PART_DEVICE_STATUS:
		return (dev | drv | common);
	case BHYVE_VIRTIO_DEV_PART_VQ_CFG:
		return (dev | drv | common | status);
	case BHYVE_VIRTIO_DEV_PART_VQ_NOTIFY_CFG:
		return (dev | drv | common | status | vq);
	default:
		return (0);
	}
}

static bool
vdev_part_value_valid(uint16_t type, const uint8_t *value, uint32_t length)
{

	switch (type) {
	case BHYVE_VIRTIO_DEV_PART_DEVICE_STATUS:
		return (length == sizeof(uint8_t) &&
		    /*
		     * ACKNOWLEDGE, DRIVER, DRIVER_OK, FEATURES_OK, SUSPEND,
		     * DEVICE_NEEDS_RESET, and FAILED are the complete VirtIO
		     * 1.4 device-status set.  Bit 5 remains reserved.
		     */
		    (value[0] & ~UINT8_C(0xdf)) == 0);
	case BHYVE_VIRTIO_DEV_PART_VQ_CFG:
		return (length == BHYVE_VIRTIO_DEV_PART_VQ_CFG_SIZE &&
		    le16dec(value + 4) <= 1 &&
		    value[6] == 0 && value[7] == 0);
	case BHYVE_VIRTIO_DEV_PART_VQ_NOTIFY_CFG:
		return (length == BHYVE_VIRTIO_DEV_PART_VQ_NOTIFY_SIZE &&
		    le32dec(value + 4) == 0);
	default:
		return (true);
	}
}

void
virtio_device_parts_iterator_init(struct virtio_device_parts_iterator *iterator,
    const void *buffer, size_t length)
{

	memset(iterator, 0, sizeof(*iterator));
	iterator->bytes = buffer;
	iterator->length = length;
}

void
virtio_device_part_headers_iterator_init(
    struct virtio_device_parts_iterator *iterator, const void *buffer,
    size_t length)
{

	virtio_device_parts_iterator_init(iterator, buffer, length);
	iterator->headers_only = true;
}

void
virtio_device_part_selection_iterator_init(
    struct virtio_device_parts_iterator *iterator, const void *buffer,
    size_t length)
{

	virtio_device_part_headers_iterator_init(iterator, buffer, length);
	iterator->independent_headers = true;
}

int
virtio_device_parts_next(struct virtio_device_parts_iterator *iterator,
    struct virtio_device_part *part)
{
	const uint8_t *header, *selector;
	uint32_t bit, value_length;
	uint16_t type;
	size_t remaining;
	bool known;

	if (iterator == NULL || part == NULL ||
	    (iterator->bytes == NULL && iterator->length != 0))
		return (EINVAL);
	if (iterator->offset == iterator->length)
		return (ENOENT);
	if (iterator->offset > iterator->length)
		return (EPROTO);
	remaining = iterator->length - iterator->offset;
	if (remaining < BHYVE_VIRTIO_DEV_PART_HEADER_SIZE)
		return (EPROTO);

	header = iterator->bytes + iterator->offset;
	type = le16dec(header);
	known = vdev_part_known(type);
	if ((header[2] & ~BHYVE_VIRTIO_DEV_PART_F_OPTIONAL) != 0 ||
	    header[3] != 0)
		return (EPROTO);
	if (!known && (header[2] & BHYVE_VIRTIO_DEV_PART_F_OPTIONAL) == 0)
		return (EOPNOTSUPP);
	selector = header + 4;
	if (known && (!vdev_part_selector_valid(type, selector) ||
	    (!iterator->independent_headers &&
	    (type < iterator->prior_type ||
	    (iterator->known_seen & vdev_part_required(type)) !=
	    vdev_part_required(type)))))
		return (EPROTO);
	if (type == BHYVE_VIRTIO_DEV_PART_DEV_FEATURES &&
	    (header[2] & BHYVE_VIRTIO_DEV_PART_F_OPTIONAL) == 0)
		return (EPROTO);
	value_length = le32dec(header + 12);
	if (!vdev_part_length_valid(type, selector, value_length) ||
	    (!iterator->headers_only &&
	    value_length > remaining - BHYVE_VIRTIO_DEV_PART_HEADER_SIZE))
		return (EPROTO);
	if (!iterator->headers_only && known && !vdev_part_value_valid(type,
	    header + BHYVE_VIRTIO_DEV_PART_HEADER_SIZE, value_length))
		return (EPROTO);
	bit = vdev_part_singleton_bit(type);
	if ((bit & iterator->singleton_seen) != 0)
		return (EPROTO);
	if (known && type == iterator->prior_type &&
	    (type == BHYVE_VIRTIO_DEV_PART_PCI_COMMON_CFG ||
	    type == BHYVE_VIRTIO_DEV_PART_VQ_CFG ||
	    type == BHYVE_VIRTIO_DEV_PART_VQ_NOTIFY_CFG) &&
	    le64dec(selector) == iterator->prior_selector)
		return (EPROTO);

	part->type = type;
	part->flags = header[2];
	part->selector = le64dec(selector);
	part->length = value_length;
	part->value = iterator->headers_only ? NULL :
	    header + BHYVE_VIRTIO_DEV_PART_HEADER_SIZE;
	iterator->offset += BHYVE_VIRTIO_DEV_PART_HEADER_SIZE +
	    (iterator->headers_only ? 0 : value_length);
	if (known) {
		iterator->prior_type = type;
		iterator->prior_selector = le64dec(selector);
		iterator->singleton_seen |= bit;
		iterator->known_seen |= vdev_part_known_bit(type);
	}
	return (0);
}

static int
vdev_part_header_append(void *buffer, size_t capacity, size_t *used,
    uint16_t type, uint8_t flags, uint64_t selector, uint32_t value_length)
{
	uint8_t selector_bytes[8], *bytes;

	if (buffer == NULL || used == NULL)
		return (EINVAL);
	memset(selector_bytes, 0, sizeof(selector_bytes));
	if (type == BHYVE_VIRTIO_DEV_PART_PCI_COMMON_CFG) {
		if (selector > UINT32_MAX)
			return (ERANGE);
		le32enc(selector_bytes, (uint32_t)selector);
	} else if (type == BHYVE_VIRTIO_DEV_PART_VQ_CFG ||
	    type == BHYVE_VIRTIO_DEV_PART_VQ_NOTIFY_CFG) {
		if (selector > UINT16_MAX)
			return (ERANGE);
		le16enc(selector_bytes, (uint16_t)selector);
	} else if (selector != 0)
		return (EINVAL);
	if (!vdev_part_known(type))
		return (EOPNOTSUPP);
	if ((flags & ~BHYVE_VIRTIO_DEV_PART_F_OPTIONAL) != 0 ||
	    (type == BHYVE_VIRTIO_DEV_PART_DEV_FEATURES &&
	    (flags & BHYVE_VIRTIO_DEV_PART_F_OPTIONAL) == 0) ||
	    !vdev_part_length_valid(type, selector_bytes, value_length))
		return (EINVAL);
	if (*used > capacity ||
	    *used > SIZE_MAX - BHYVE_VIRTIO_DEV_PART_HEADER_SIZE)
		return (EOVERFLOW);
	if (BHYVE_VIRTIO_DEV_PART_HEADER_SIZE > capacity - *used)
		return (ENOSPC);
	/*
	 * This is a state builder, not an in-place transform.  In particular,
	 * do not let the header publication overwrite the caller's cursor.
	 */
	if (virtio_state_ranges_overlap(used, sizeof(*used),
	    (const uint8_t *)buffer + *used,
	    BHYVE_VIRTIO_DEV_PART_HEADER_SIZE))
		return (EINVAL);

	bytes = buffer;
	bytes += *used;
	memset(bytes, 0, BHYVE_VIRTIO_DEV_PART_HEADER_SIZE);
	le16enc(bytes, type);
	bytes[2] = flags;
	memcpy(bytes + 4, selector_bytes, sizeof(selector_bytes));
	le32enc(bytes + 12, value_length);
	*used += BHYVE_VIRTIO_DEV_PART_HEADER_SIZE;
	return (0);
}

int
virtio_device_part_header_append(void *buffer, size_t capacity, size_t *used,
    uint16_t type, uint8_t flags, uint64_t selector, uint32_t value_length)
{

	return (vdev_part_header_append(buffer, capacity, used, type, flags,
	    selector, value_length));
}

int
virtio_device_part_append(void *buffer, size_t capacity, size_t *used,
    uint16_t type, uint8_t flags, uint64_t selector, const void *value,
    uint32_t value_length)
{
	uint8_t header[BHYVE_VIRTIO_DEV_PART_HEADER_SIZE];
	size_t header_used, original;
	int error;

	if (buffer == NULL || used == NULL ||
	    (value == NULL && value_length != 0))
		return (EINVAL);
	header_used = 0;
	error = vdev_part_header_append(header, sizeof(header), &header_used,
	    type, flags, selector, value_length);
	if (error != 0)
		return (error);
	if (!vdev_part_value_valid(type, value, value_length))
		return (EINVAL);
	original = *used;
	if (original > capacity || value_length > capacity - original ||
	    BHYVE_VIRTIO_DEV_PART_HEADER_SIZE >
	    capacity - original - value_length)
		return (ENOSPC);
	/*
	 * The header is committed before the value copy below.  Reject source or
	 * cursor aliases with the destination interval so failed appends leave
	 * both the byte stream and its caller-owned cursor unchanged.
	 */
	if (virtio_state_ranges_overlap(value, value_length,
	    (const uint8_t *)buffer + original,
	    BHYVE_VIRTIO_DEV_PART_HEADER_SIZE + value_length) ||
	    virtio_state_ranges_overlap(used, sizeof(*used),
	    (const uint8_t *)buffer + original,
	    BHYVE_VIRTIO_DEV_PART_HEADER_SIZE + value_length))
		return (EINVAL);
	memcpy((uint8_t *)buffer + original, header, sizeof(header));
	*used += header_used;
	if (value_length != 0)
		memcpy((uint8_t *)buffer + *used, value, value_length);
	*used += value_length;
	return (0);
}
