/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/endian.h>

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "virtio_iommu_protocol.h"
#include "virtio_iommu_state.h"
#include "virtio_state_range.h"

static bool
viommu_bytes_zero(const uint8_t *bytes, size_t length)
{

	for (size_t i = 0; i < length; i++) {
		if (bytes[i] != 0)
			return (false);
	}
	return (true);
}

int
virtio_iommu_request_decode_bounded(const void *buffer, size_t available,
    size_t length, struct virtio_iommu_request *request)
{
	struct virtio_iommu_request candidate;
	const uint8_t *bytes;
	size_t expected;

	if (buffer == NULL || request == NULL)
		return (EINVAL);
	if (length < 1 || available < 1)
		return (EMSGSIZE);
	bytes = buffer;
	switch (bytes[0]) {
	case BHYVE_VIOMMU_T_ATTACH:
		expected = BHYVE_VIOMMU_ATTACH_INPUT_SIZE;
		break;
	case BHYVE_VIOMMU_T_DETACH:
		expected = BHYVE_VIOMMU_DETACH_INPUT_SIZE;
		break;
	case BHYVE_VIOMMU_T_MAP:
		expected = BHYVE_VIOMMU_MAP_INPUT_SIZE;
		break;
	case BHYVE_VIOMMU_T_UNMAP:
		expected = BHYVE_VIOMMU_UNMAP_INPUT_SIZE;
		break;
	case BHYVE_VIOMMU_T_PROBE:
		expected = BHYVE_VIOMMU_PROBE_INPUT_SIZE;
		break;
	default:
		return (EOPNOTSUPP);
	}
	if (length != expected)
		return (EMSGSIZE);
	if (available < expected)
		return (EMSGSIZE);
	if (virtio_state_ranges_overlap(buffer, expected, request,
	    sizeof(*request)))
		return (EINVAL);
	memset(&candidate, 0, sizeof(candidate));
	candidate.type = bytes[0];
	switch (candidate.type) {
	case BHYVE_VIOMMU_T_ATTACH:
		candidate.domain = le32dec(bytes + 4);
		candidate.endpoint = le32dec(bytes + 8);
		candidate.flags = le32dec(bytes + 12);
		/* Section 5.13.6.3.2 requires this reserved field to be zero. */
		if (!viommu_bytes_zero(bytes + 16, 4))
			return (EINVAL);
		break;
	case BHYVE_VIOMMU_T_DETACH:
		candidate.domain = le32dec(bytes + 4);
		candidate.endpoint = le32dec(bytes + 8);
		/* The DETACH-specific reserved field is explicitly ignored. */
		break;
	case BHYVE_VIOMMU_T_MAP:
		candidate.domain = le32dec(bytes + 4);
		candidate.virtual_start = le64dec(bytes + 8);
		candidate.virtual_end = le64dec(bytes + 16);
		candidate.physical_start = le64dec(bytes + 24);
		candidate.flags = le32dec(bytes + 32);
		break;
	case BHYVE_VIOMMU_T_UNMAP:
		candidate.domain = le32dec(bytes + 4);
		candidate.virtual_start = le64dec(bytes + 8);
		candidate.virtual_end = le64dec(bytes + 16);
		/*
		 * The device may reject a nonzero UNMAP reserved field.  Doing
		 * so gives deterministic validation without changing mappings.
		 */
		if (!viommu_bytes_zero(bytes + 24, 4))
			return (EINVAL);
		break;
	case BHYVE_VIOMMU_T_PROBE:
		candidate.endpoint = le32dec(bytes + 4);
		/* PROBE's 64 reserved bytes are ignored by section 5.13.6.7. */
		break;
	}
	*request = candidate;
	return (0);
}

int
virtio_iommu_request_decode(const void *buffer, size_t length,
    struct virtio_iommu_request *request)
{

	return (virtio_iommu_request_decode_bounded(buffer, length, length,
	    request));
}

void
virtio_iommu_status_encode(uint8_t status,
    uint8_t output[BHYVE_VIOMMU_REQUEST_TAIL_SIZE])
{

	memset(output, 0, BHYVE_VIOMMU_REQUEST_TAIL_SIZE);
	output[0] = status;
}

void
virtio_iommu_fault_encode(const struct virtio_iommu_fault *fault,
    uint8_t output[BHYVE_VIOMMU_FAULT_SIZE])
{
	uint8_t wire[BHYVE_VIOMMU_FAULT_SIZE];

	memset(wire, 0, sizeof(wire));
	wire[0] = fault->reason;
	le32enc(wire + 4, fault->flags);
	le32enc(wire + 8, fault->endpoint);
	le64enc(wire + 16, fault->address);
	memmove(output, wire, sizeof(wire));
}
