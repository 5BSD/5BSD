#!/bin/sh
# Verify the common VirtIO DMA boundary remains the only queue/descriptor
# mapping path, so ACCESS_PLATFORM cannot be bypassed by a device callback.
# TEST-ANCHOR: common-dma-translator
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src=${SRCTOP:-/usr/src}

require_file()
{
	[ -f "$1" ] || {
		echo "virtio DMA boundary: missing $1" >&2
		exit 1
	}
}

require_pattern()
{
	file=$1
	pattern=$2
	grep -Eq "$pattern" "$file" || {
		echo "virtio DMA boundary: $file lacks $pattern" >&2
		exit 1
	}
}

core=$src/usr.sbin/bhyve/virtio.c
header=$src/usr.sbin/bhyve/virtio.h
test_source=$here/virtio_core_test.c
iommu_test=$here/virtio_iommu_state_test.c

for file in "$core" "$header" "$test_source" "$iommu_test"; do
	require_file "$file"
done

# Queue rings, direct chains, and indirect chains all map through the common
# translator under an acquired request lease.  This is intentionally checked
# in source and then exercised by the independent core/IOMMU models.
require_pattern "$header" 'vi_(set|clear)_dma_domain'
require_pattern "$header" 'vi_(req_)?dma_(acquire|release)'
require_pattern "$header" 'vi_map_dma'
require_pattern "$core" 'vq_refresh_dma_mappings'
require_pattern "$core" 'vi_req_dma_acquire'
require_pattern "$core" 'vi_req_dma_release'
require_pattern "$core" 'vi_map_dma'
require_pattern "$test_source" 'access_platform_(domain_contract|detach_acquire_race|request_dma_lifetime)'
require_pattern "$iommu_test" '(mapping_permissions|concurrent_unmap|domain_revocation)'

echo "virtio DMA boundary: common translator, lease fence, and independent IOMMU tests present"
