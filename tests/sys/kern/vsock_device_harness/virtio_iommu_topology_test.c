/*
 * Independent PCI requester-selection tests for VirtIO 1.4 section 5.13.
 */
#include <sys/param.h>

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include "virtio_iommu_topology.c"

ATF_TC_WITHOUT_HEAD(selects_only_modern_virtio_endpoints);
ATF_TC_BODY(selects_only_modern_virtio_endpoints, tc)
{
	const struct virtio_iommu_topology_entry entries[] = {
		{ .requester_id = 0x28, .virtio = true, .modern = true },
		{ .requester_id = 0x30, .virtio = true, .modern = false },
		{ .requester_id = 0x38, .virtio = false, .modern = true },
		{ .requester_id = 0x40, .virtio = true, .modern = true,
		    .iommu = true },
		{ .requester_id = 0x48, .virtio = true, .modern = true },
		{ .requester_id = 0x50, .virtio = true, .modern = true,
		    .access_platform_ineligible = true },
	};
	uint16_t endpoints[4], iommu;
	size_t count;

	count = 0;
	ATF_REQUIRE_EQ(virtio_iommu_topology_build(entries,
	    nitems(entries), &iommu, endpoints, nitems(endpoints), &count), 0);
	ATF_CHECK_EQ(iommu, 0x40);
	ATF_REQUIRE_EQ(count, 2);
	ATF_CHECK_EQ(endpoints[0], 0x28);
	ATF_CHECK_EQ(endpoints[1], 0x48);
}

ATF_TC_WITHOUT_HEAD(rejects_topology_with_only_ineligible_endpoint);
ATF_TC_BODY(rejects_topology_with_only_ineligible_endpoint, tc)
{
	const struct virtio_iommu_topology_entry entries[] = {
		{ .requester_id = 0x40, .virtio = true, .modern = true,
		    .iommu = true },
		{ .requester_id = 0x48, .virtio = true, .modern = true,
		    .access_platform_ineligible = true },
	};
	uint16_t endpoint, iommu;
	size_t count;

	ATF_CHECK_EQ(virtio_iommu_topology_build(entries, nitems(entries),
	    &iommu, &endpoint, 1, &count), ENODEV);
}

ATF_TC_WITHOUT_HEAD(provider_ineligible_flag_does_not_hide_provider);
ATF_TC_BODY(provider_ineligible_flag_does_not_hide_provider, tc)
{
	const struct virtio_iommu_topology_entry entries[] = {
		{ .requester_id = 0x40, .virtio = true, .modern = true,
		    .iommu = true, .access_platform_ineligible = true },
		{ .requester_id = 0x48, .virtio = true, .modern = true },
	};
	uint16_t endpoint, iommu;
	size_t count;

	ATF_REQUIRE_EQ(virtio_iommu_topology_build(entries, nitems(entries),
	    &iommu, &endpoint, 1, &count), 0);
	ATF_CHECK_EQ(iommu, 0x40);
	ATF_CHECK_EQ(count, 1);
	ATF_CHECK_EQ(endpoint, 0x48);
}

ATF_TC_WITHOUT_HEAD(rejects_ambiguous_or_empty_topologies);
ATF_TC_BODY(rejects_ambiguous_or_empty_topologies, tc)
{
	const struct virtio_iommu_topology_entry duplicate_iommu[] = {
		{ .requester_id = 0x40, .virtio = true, .modern = true,
		    .iommu = true },
		{ .requester_id = 0x48, .virtio = true, .modern = true,
		    .iommu = true },
	};
	const struct virtio_iommu_topology_entry no_iommu[] = {
		{ .requester_id = 0x28, .virtio = true, .modern = true },
	};
	const struct virtio_iommu_topology_entry no_endpoint[] = {
		{ .requester_id = 0x40, .virtio = true, .modern = true,
		    .iommu = true },
	};
	uint16_t endpoints[2], iommu;
	size_t count;

	ATF_CHECK_EQ(virtio_iommu_topology_build(duplicate_iommu,
	    nitems(duplicate_iommu), &iommu, endpoints, nitems(endpoints),
	    &count), EEXIST);
	ATF_CHECK_EQ(virtio_iommu_topology_build(no_iommu,
	    nitems(no_iommu), &iommu, endpoints, nitems(endpoints), &count),
	    ENODEV);
	ATF_CHECK_EQ(virtio_iommu_topology_build(no_endpoint,
	    nitems(no_endpoint), &iommu, endpoints, nitems(endpoints), &count),
	    ENODEV);
}

ATF_TC_WITHOUT_HEAD(rejects_duplicate_and_excess_endpoints);
ATF_TC_BODY(rejects_duplicate_and_excess_endpoints, tc)
{
	const struct virtio_iommu_topology_entry duplicate_endpoint[] = {
		{ .requester_id = 0x40, .virtio = true, .modern = true,
		    .iommu = true },
		{ .requester_id = 0x28, .virtio = true, .modern = true },
		{ .requester_id = 0x28, .virtio = true, .modern = true },
	};
	const struct virtio_iommu_topology_entry two_endpoints[] = {
		{ .requester_id = 0x40, .virtio = true, .modern = true,
		    .iommu = true },
		{ .requester_id = 0x28, .virtio = true, .modern = true },
		{ .requester_id = 0x30, .virtio = true, .modern = true },
	};
	uint16_t endpoints[2], iommu;
	size_t count;

	iommu = 0xa5a5;
	endpoints[0] = 0x5a5a;
	endpoints[1] = 0x5a5a;
	count = 0x55;
	ATF_CHECK_EQ(virtio_iommu_topology_build(duplicate_endpoint,
	    nitems(duplicate_endpoint), &iommu, endpoints, nitems(endpoints),
	    &count), EEXIST);
	ATF_CHECK_EQ(iommu, 0xa5a5);
	ATF_CHECK_EQ(endpoints[0], 0x5a5a);
	ATF_CHECK_EQ(endpoints[1], 0x5a5a);
	ATF_CHECK_EQ(count, 0x55);
	ATF_CHECK_EQ(virtio_iommu_topology_build(two_endpoints,
	    nitems(two_endpoints), &iommu, endpoints, 1, &count), E2BIG);
	ATF_CHECK_EQ(iommu, 0xa5a5);
	ATF_CHECK_EQ(endpoints[0], 0x5a5a);
	ATF_CHECK_EQ(endpoints[1], 0x5a5a);
	ATF_CHECK_EQ(count, 0x55);
}

ATF_TC_WITHOUT_HEAD(rejects_publication_aliases);
ATF_TC_BODY(rejects_publication_aliases, tc)
{
	struct virtio_iommu_topology_entry entries[] = {
		{ .requester_id = 0x40, .virtio = true, .modern = true,
		    .iommu = true },
		{ .requester_id = 0x28, .virtio = true, .modern = true },
		{ .requester_id = 0x30, .virtio = true, .modern = true },
	};
	struct virtio_iommu_topology_entry before[nitems(entries)];
	_Alignas(size_t) uint16_t shared[sizeof(size_t) / sizeof(uint16_t)];
	uint16_t endpoints[2], iommu;
	size_t count;

	memcpy(before, entries, sizeof(before));
	count = 0x55;
	ATF_CHECK_EQ(virtio_iommu_topology_build(entries, nitems(entries),
	    &iommu, (uint16_t *)(void *)&entries[0], 2, &count), EINVAL);
	ATF_CHECK(memcmp(entries, before, sizeof(entries)) == 0);
	ATF_CHECK_EQ(count, 0x55);

	memset(shared, 0xa5, sizeof(shared));
	ATF_CHECK_EQ(virtio_iommu_topology_build(entries, nitems(entries),
	    &iommu, shared, nitems(shared), (size_t *)(void *)shared), EINVAL);
	ATF_CHECK_EQ(shared[0], 0xa5a5);

	count = 0x55;
	ATF_CHECK_EQ(virtio_iommu_topology_build(entries, nitems(entries),
	    endpoints, endpoints, nitems(endpoints), &count), EINVAL);
	ATF_CHECK_EQ(count, 0x55);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, selects_only_modern_virtio_endpoints);
	ATF_TP_ADD_TC(tp, rejects_topology_with_only_ineligible_endpoint);
	ATF_TP_ADD_TC(tp, provider_ineligible_flag_does_not_hide_provider);
	ATF_TP_ADD_TC(tp, rejects_ambiguous_or_empty_topologies);
	ATF_TP_ADD_TC(tp, rejects_duplicate_and_excess_endpoints);
	ATF_TP_ADD_TC(tp, rejects_publication_aliases);
	return (atf_no_error());
}
