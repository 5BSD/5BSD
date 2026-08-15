/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/endian.h>

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "virtio_iommu_viot.h"
#include "virtio_state_range.h"

#define	VIOT_NODE_PCI_RANGE		1U
#define	VIOT_NODE_VIRTIO_IOMMU_PCI	3U

int
virtio_iommu_viot_size(size_t endpoint_count, size_t *size)
{
	size_t payload;

	if (size == NULL || endpoint_count == 0 ||
	    endpoint_count > (UINT16_MAX - 1) ||
	    endpoint_count > (SIZE_MAX - BHYVE_VIOT_TABLE_PREFIX_SIZE -
	    BHYVE_VIOT_PCI_IOMMU_SIZE) / BHYVE_VIOT_PCI_RANGE_SIZE)
		return (EINVAL);
	payload = BHYVE_VIOT_TABLE_PREFIX_SIZE +
	    endpoint_count * BHYVE_VIOT_PCI_RANGE_SIZE +
	    BHYVE_VIOT_PCI_IOMMU_SIZE;
	if (payload > UINT32_MAX)
		return (EOVERFLOW);
	*size = payload;
	return (0);
}

int
virtio_iommu_viot_encode(uint16_t iommu_bdf, const uint16_t *endpoints,
    size_t endpoint_count, void *buffer, size_t length)
{
	uint8_t *bytes, *node;
	size_t expected, iommu_offset;
	int error;

	error = virtio_iommu_viot_size(endpoint_count, &expected);
	if (error != 0)
		return (error);
	if (endpoints == NULL || buffer == NULL || length != expected)
		return (EINVAL);
	if (endpoint_count > SIZE_MAX / sizeof(*endpoints) ||
	    virtio_state_ranges_overlap(buffer, length, endpoints,
	    endpoint_count * sizeof(*endpoints)))
		return (EINVAL);
	for (size_t i = 0; i < endpoint_count; i++) {
		if (endpoints[i] == iommu_bdf)
			return (EINVAL);
		for (size_t j = 0; j < i; j++) {
			if (endpoints[i] == endpoints[j])
				return (EEXIST);
		}
	}
	iommu_offset = BHYVE_VIOT_ACPI_HEADER_SIZE +
	    BHYVE_VIOT_TABLE_PREFIX_SIZE +
	    endpoint_count * BHYVE_VIOT_PCI_RANGE_SIZE;
	if (iommu_offset > UINT16_MAX)
		return (EOVERFLOW);

	bytes = buffer;
	memset(bytes, 0, length);
	le16enc(bytes + 0, (uint16_t)(endpoint_count + 1));
	le16enc(bytes + 2, BHYVE_VIOT_ACPI_HEADER_SIZE +
	    BHYVE_VIOT_TABLE_PREFIX_SIZE);

	node = bytes + BHYVE_VIOT_TABLE_PREFIX_SIZE;
	for (size_t i = 0; i < endpoint_count; i++) {
		node[0] = VIOT_NODE_PCI_RANGE;
		le16enc(node + 2, BHYVE_VIOT_PCI_RANGE_SIZE);
		le32enc(node + 4, endpoints[i]);
		/* PCI segment range is exactly segment zero. */
		le16enc(node + 8, 0);
		le16enc(node + 10, 0);
		le16enc(node + 12, endpoints[i]);
		le16enc(node + 14, endpoints[i]);
		le16enc(node + 16, (uint16_t)iommu_offset);
		node += BHYVE_VIOT_PCI_RANGE_SIZE;
	}
	node[0] = VIOT_NODE_VIRTIO_IOMMU_PCI;
	le16enc(node + 2, BHYVE_VIOT_PCI_IOMMU_SIZE);
	le16enc(node + 4, 0);
	le16enc(node + 6, iommu_bdf);
	return (0);
}
