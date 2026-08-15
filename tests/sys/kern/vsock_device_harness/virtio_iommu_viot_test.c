/*
 * Independent ACPI VIOT revision 1 PCI-topology tests.
 */
#include <sys/endian.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include "virtio_iommu_viot.c"

ATF_TC_WITHOUT_HEAD(exact_two_endpoint_layout);
ATF_TC_BODY(exact_two_endpoint_layout, tc)
{
	const uint16_t endpoints[] = { 0x20, 0x39 };
	uint8_t bytes[76];
	size_t size;

	ATF_REQUIRE_EQ(virtio_iommu_viot_size(2, &size), 0);
	ATF_REQUIRE_EQ(size, sizeof(bytes));
	memset(bytes, 0xa5, sizeof(bytes));
	ATF_REQUIRE_EQ(virtio_iommu_viot_encode(0x28, endpoints, 2, bytes,
	    sizeof(bytes)), 0);
	ATF_CHECK_EQ(le16dec(bytes + 0), 3);
	ATF_CHECK_EQ(le16dec(bytes + 2), 48);
	for (size_t i = 4; i < 12; i++)
		ATF_CHECK_EQ(bytes[i], 0);

	ATF_CHECK_EQ(bytes[12], 1);
	ATF_CHECK_EQ(bytes[13], 0);
	ATF_CHECK_EQ(le16dec(bytes + 14), 24);
	ATF_CHECK_EQ(le32dec(bytes + 16), 0x20);
	ATF_CHECK_EQ(le16dec(bytes + 20), 0);
	ATF_CHECK_EQ(le16dec(bytes + 22), 0);
	ATF_CHECK_EQ(le16dec(bytes + 24), 0x20);
	ATF_CHECK_EQ(le16dec(bytes + 26), 0x20);
	ATF_CHECK_EQ(le16dec(bytes + 28), 96);
	for (size_t i = 30; i < 36; i++)
		ATF_CHECK_EQ(bytes[i], 0);

	ATF_CHECK_EQ(bytes[36], 1);
	ATF_CHECK_EQ(le16dec(bytes + 38), 24);
	ATF_CHECK_EQ(le32dec(bytes + 40), 0x39);
	ATF_CHECK_EQ(le16dec(bytes + 48), 0x39);
	ATF_CHECK_EQ(le16dec(bytes + 50), 0x39);
	ATF_CHECK_EQ(le16dec(bytes + 52), 96);

	ATF_CHECK_EQ(bytes[60], 3);
	ATF_CHECK_EQ(bytes[61], 0);
	ATF_CHECK_EQ(le16dec(bytes + 62), 16);
	ATF_CHECK_EQ(le16dec(bytes + 64), 0);
	ATF_CHECK_EQ(le16dec(bytes + 66), 0x28);
	for (size_t i = 68; i < sizeof(bytes); i++)
		ATF_CHECK_EQ(bytes[i], 0);
}

ATF_TC_WITHOUT_HEAD(rejects_ambiguous_topology);
ATF_TC_BODY(rejects_ambiguous_topology, tc)
{
	const uint16_t duplicate[] = { 0x20, 0x20 };
	const uint16_t self[] = { 0x20, 0x28 };
	union {
		uint8_t bytes[76];
		uint16_t endpoints[38];
	} storage;
	uint8_t *bytes;
	size_t size;

	bytes = storage.bytes;
	ATF_CHECK_EQ(virtio_iommu_viot_size(0, &size), EINVAL);
	ATF_CHECK_EQ(virtio_iommu_viot_size(1, NULL), EINVAL);
	ATF_CHECK_EQ(virtio_iommu_viot_encode(0x28, duplicate, 2, bytes,
	    sizeof(storage.bytes)), EEXIST);
	ATF_CHECK_EQ(virtio_iommu_viot_encode(0x28, self, 2, bytes,
	    sizeof(storage.bytes)), EINVAL);
	ATF_CHECK_EQ(virtio_iommu_viot_encode(0x28, duplicate, 2, bytes,
	    sizeof(storage.bytes) - 1), EINVAL);
	ATF_CHECK_EQ(virtio_iommu_viot_encode(0x28, NULL, 2, bytes,
	    sizeof(storage.bytes)), EINVAL);
	storage.endpoints[0] = 0x20;
	storage.endpoints[1] = 0x39;
	ATF_CHECK_EQ(virtio_iommu_viot_encode(0x28, storage.endpoints, 2,
	    storage.bytes, sizeof(storage.bytes)), EINVAL);
	ATF_CHECK_EQ(storage.endpoints[0], 0x20);
	ATF_CHECK_EQ(storage.endpoints[1], 0x39);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, exact_two_endpoint_layout);
	ATF_TP_ADD_TC(tp, rejects_ambiguous_topology);
	return (atf_no_error());
}
