/*
 * Independent VirtIO 1.4 section 5.13 wire-format tests.
 */
#include <sys/param.h>
#include <sys/endian.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include "virtio_iommu_protocol.c"

#define	DOC_ATTACH	1
#define	DOC_DETACH	2
#define	DOC_MAP		3
#define	DOC_UNMAP	4
#define	DOC_PROBE	5
#define	DOC_FAULT_SIZE	24U
#define	DOC_REQUEST_HEADER_SIZE	4U
#define	ALIAS_STORAGE_SIZE	128U

ATF_TC_WITHOUT_HEAD(fixed_request_layouts);
ATF_TC_BODY(fixed_request_layouts, tc)
{
	struct virtio_iommu_request request;
	uint8_t bytes[72];

	memset(bytes, 0, sizeof(bytes));
	bytes[0] = DOC_ATTACH;
	le32enc(bytes + 4, 7);
	le32enc(bytes + 8, 0x108);
	le32enc(bytes + 12, 1);
	ATF_REQUIRE_EQ(virtio_iommu_request_decode(bytes, 20, &request), 0);
	ATF_CHECK_EQ(request.type, DOC_ATTACH);
	ATF_CHECK_EQ(request.domain, 7);
	ATF_CHECK_EQ(request.endpoint, 0x108);
	ATF_CHECK_EQ(request.flags, 1);

	memset(bytes, 0xa5, sizeof(bytes));
	bytes[0] = DOC_DETACH;
	le32enc(bytes + 4, 8);
	le32enc(bytes + 8, 0x110);
	ATF_REQUIRE_EQ(virtio_iommu_request_decode(bytes, 20, &request), 0);
	ATF_CHECK_EQ(request.type, DOC_DETACH);
	ATF_CHECK_EQ(request.domain, 8);
	ATF_CHECK_EQ(request.endpoint, 0x110);

	memset(bytes, 0, sizeof(bytes));
	bytes[0] = DOC_MAP;
	le32enc(bytes + 4, 9);
	le64enc(bytes + 8, UINT64_C(0x1000));
	le64enc(bytes + 16, UINT64_C(0x2fff));
	le64enc(bytes + 24, UINT64_C(0x81000));
	le32enc(bytes + 32, 3);
	ATF_REQUIRE_EQ(virtio_iommu_request_decode(bytes, 36, &request), 0);
	ATF_CHECK_EQ(request.virtual_start, UINT64_C(0x1000));
	ATF_CHECK_EQ(request.virtual_end, UINT64_C(0x2fff));
	ATF_CHECK_EQ(request.physical_start, UINT64_C(0x81000));
	ATF_CHECK_EQ(request.flags, 3);

	memset(bytes, 0, sizeof(bytes));
	bytes[0] = DOC_UNMAP;
	le32enc(bytes + 4, 10);
	le64enc(bytes + 8, UINT64_C(0x4000));
	le64enc(bytes + 16, UINT64_C(0x4fff));
	ATF_REQUIRE_EQ(virtio_iommu_request_decode(bytes, 28, &request), 0);
	ATF_CHECK_EQ(request.domain, 10);
	ATF_CHECK_EQ(request.virtual_start, UINT64_C(0x4000));
	ATF_CHECK_EQ(request.virtual_end, UINT64_C(0x4fff));

	memset(bytes, 0x5a, sizeof(bytes));
	bytes[0] = DOC_PROBE;
	le32enc(bytes + 4, 0x118);
	ATF_REQUIRE_EQ(virtio_iommu_request_decode(bytes, 72, &request), 0);
	ATF_CHECK_EQ(request.endpoint, 0x118);
}

/*
 * VirtIO 1.4 section 5.13.6.2 requires the device to ignore the three
 * reserved header bytes for every defined request.  Keep this separate from
 * the layout vectors so an incidental memset pattern cannot be mistaken for
 * coverage of that interoperability rule.
 */
ATF_TC_WITHOUT_HEAD(header_reserved_bytes_are_ignored);
ATF_TC_BODY(header_reserved_bytes_are_ignored, tc)
{
	static const struct {
		uint8_t type;
		size_t length;
	} cases[] = {
		{ DOC_ATTACH, 20 },
		{ DOC_DETACH, 20 },
		{ DOC_MAP, 36 },
		{ DOC_UNMAP, 28 },
		{ DOC_PROBE, 72 },
	};
	struct virtio_iommu_request request;
	uint8_t bytes[72];
	size_t i;

	for (i = 0; i < nitems(cases); i++) {
		memset(bytes, 0, sizeof(bytes));
		bytes[0] = cases[i].type;
		bytes[1] = 0x5a;
		bytes[2] = 0xa5;
		bytes[DOC_REQUEST_HEADER_SIZE - 1] = 0xff;
		ATF_REQUIRE_EQ(virtio_iommu_request_decode(bytes,
		    cases[i].length, &request), 0);
		ATF_CHECK_EQ(request.type, cases[i].type);
	}
}

ATF_TC_WITHOUT_HEAD(length_unknown_and_reserved_validation);
ATF_TC_BODY(length_unknown_and_reserved_validation, tc)
{
	struct virtio_iommu_request before, request;
	uint8_t bytes[72];

	memset(&request, 0xa5, sizeof(request));
	before = request;
	memset(bytes, 0, sizeof(bytes));
	bytes[0] = DOC_ATTACH;
	ATF_CHECK_EQ(virtio_iommu_request_decode(bytes, 19, &request),
	    EMSGSIZE);
	ATF_CHECK_EQ(virtio_iommu_request_decode(bytes, 21, &request),
	    EMSGSIZE);
	bytes[16] = 1;
	ATF_CHECK_EQ(virtio_iommu_request_decode(bytes, 20, &request), EINVAL);
	ATF_CHECK(memcmp(&request, &before, sizeof(request)) == 0);
	memset(bytes, 0, sizeof(bytes));
	bytes[0] = DOC_UNMAP;
	bytes[24] = 1;
	ATF_CHECK_EQ(virtio_iommu_request_decode(bytes, 28, &request), EINVAL);
	bytes[0] = 0xff;
	ATF_CHECK_EQ(virtio_iommu_request_decode(bytes, 28, &request),
	    EOPNOTSUPP);
	ATF_CHECK_EQ(virtio_iommu_request_decode(bytes, 0, &request),
	    EMSGSIZE);
	ATF_CHECK_EQ(virtio_iommu_request_decode(NULL, 0, &request), EINVAL);
}

ATF_TC_WITHOUT_HEAD(request_alias_is_rejected_without_mutation);
ATF_TC_BODY(request_alias_is_rejected_without_mutation, tc)
{
	union {
		max_align_t alignment;
		uint8_t bytes[ALIAS_STORAGE_SIZE];
	} storage;
	uint8_t before[ALIAS_STORAGE_SIZE];

	memset(storage.bytes, 0, sizeof(storage.bytes));
	storage.bytes[0] = DOC_ATTACH;
	le32enc(storage.bytes + 4, 7);
	le32enc(storage.bytes + 8, 0x108);
	memcpy(before, storage.bytes, sizeof(before));
	ATF_CHECK_EQ(virtio_iommu_request_decode(storage.bytes, 20,
	    (struct virtio_iommu_request *)(void *)storage.bytes), EINVAL);
	ATF_CHECK(memcmp(storage.bytes, before, sizeof(before)) == 0);
}

ATF_TC_WITHOUT_HEAD(status_tail_is_exact);
ATF_TC_BODY(status_tail_is_exact, tc)
{
	uint8_t output[4] = { 0xa5, 0xa5, 0xa5, 0xa5 };

	virtio_iommu_status_encode(7, output);
	ATF_CHECK_EQ(output[0], 7);
	ATF_CHECK_EQ(output[1], 0);
	ATF_CHECK_EQ(output[2], 0);
	ATF_CHECK_EQ(output[3], 0);
}

ATF_TC_WITHOUT_HEAD(fault_event_is_exact);
ATF_TC_BODY(fault_event_is_exact, tc)
{
	struct virtio_iommu_fault fault;
	uint8_t output[24];

	fault = (struct virtio_iommu_fault) {
		.reason = 2,
		.flags = (1U << 0) | (1U << 8),
		.endpoint = 0x108,
		.address = UINT64_C(0x123456789abcdef0),
	};
	memset(output, 0xa5, sizeof(output));
	virtio_iommu_fault_encode(&fault, output);
	ATF_CHECK_EQ(output[0], 2);
	ATF_CHECK_EQ(output[1], 0);
	ATF_CHECK_EQ(le32dec(output + 4), UINT32_C(0x101));
	ATF_CHECK_EQ(le32dec(output + 8), UINT32_C(0x108));
	ATF_CHECK_EQ(le32dec(output + 12), 0);
	ATF_CHECK_EQ(le64dec(output + 16),
	    UINT64_C(0x123456789abcdef0));
}

ATF_TC_WITHOUT_HEAD(fault_event_alias_is_staged);
ATF_TC_BODY(fault_event_alias_is_staged, tc)
{
	union {
		max_align_t alignment;
		uint8_t bytes[ALIAS_STORAGE_SIZE];
	} storage;
	struct virtio_iommu_fault *fault;

	memset(storage.bytes, 0xa5, sizeof(storage.bytes));
	fault = (struct virtio_iommu_fault *)(void *)storage.bytes;
	*fault = (struct virtio_iommu_fault) {
		.reason = 2,
		.flags = UINT32_C(0x101),
		.endpoint = UINT32_C(0x108),
		.address = UINT64_C(0x123456789abcdef0),
	};
	virtio_iommu_fault_encode(fault, storage.bytes);
	ATF_CHECK_EQ(storage.bytes[0], 2);
	ATF_CHECK_EQ(le32dec(storage.bytes + 4), UINT32_C(0x101));
	ATF_CHECK_EQ(le32dec(storage.bytes + 8), UINT32_C(0x108));
	ATF_CHECK_EQ(le32dec(storage.bytes + 12), 0);
	ATF_CHECK_EQ(le64dec(storage.bytes + 16),
	    UINT64_C(0x123456789abcdef0));
	ATF_CHECK_EQ(storage.bytes[DOC_FAULT_SIZE], 0xa5);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, fault_event_alias_is_staged);
	ATF_TP_ADD_TC(tp, fixed_request_layouts);
	ATF_TP_ADD_TC(tp, header_reserved_bytes_are_ignored);
	ATF_TP_ADD_TC(tp, length_unknown_and_reserved_validation);
	ATF_TP_ADD_TC(tp, request_alias_is_rejected_without_mutation);
	ATF_TP_ADD_TC(tp, status_tail_is_exact);
	ATF_TP_ADD_TC(tp, fault_event_is_exact);
	return (atf_no_error());
}
