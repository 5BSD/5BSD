/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/endian.h>

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "virtio_iommu_config.h"
#include "virtio_iommu_state.h"

int
virtio_iommu_config_encode(const struct virtio_iommu_config_values *values,
    uint64_t offered_features, bool bypass,
    uint8_t output[BHYVE_VIOMMU_CONFIG_SIZE])
{

	if (values == NULL || output == NULL || values->page_size_mask == 0 ||
	    values->input_start > values->input_end ||
	    values->domain_start > values->domain_end ||
	    (bypass && (offered_features &
	    BHYVE_VIOMMU_F_BYPASS_CONFIG) == 0))
		return (EINVAL);
	memset(output, 0, BHYVE_VIOMMU_CONFIG_SIZE);
	le64enc(output + 0, values->page_size_mask);
	if ((offered_features & BHYVE_VIOMMU_F_INPUT_RANGE) != 0) {
		le64enc(output + 8, values->input_start);
		le64enc(output + 16, values->input_end);
	}
	if ((offered_features & BHYVE_VIOMMU_F_DOMAIN_RANGE) != 0) {
		le32enc(output + 24, values->domain_start);
		le32enc(output + 28, values->domain_end);
	}
	if ((offered_features & BHYVE_VIOMMU_F_PROBE) != 0)
		le32enc(output + 32, values->probe_size);
	if ((offered_features & BHYVE_VIOMMU_F_BYPASS_CONFIG) != 0)
		output[BHYVE_VIOMMU_CONFIG_BYPASS_OFFSET] = bypass ? 1 : 0;
	return (0);
}

int
virtio_iommu_config_write(struct virtio_iommu_state *state,
    uint64_t negotiated_features, size_t offset, size_t size, uint32_t value)
{

	if (state == NULL ||
	    (negotiated_features & BHYVE_VIOMMU_F_BYPASS_CONFIG) == 0 ||
	    offset != BHYVE_VIOMMU_CONFIG_BYPASS_OFFSET || size != 1 ||
	    value > 1)
		return (EINVAL);
	virtio_iommu_set_default_bypass(state, value != 0);
	return (0);
}
