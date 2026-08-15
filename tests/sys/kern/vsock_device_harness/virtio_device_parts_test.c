/*
 * Independent VirtIO 1.4 section 2.14 device-parts tests.
 */
#include <sys/endian.h>

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include "virtio_device_parts.c"
#include "virtio_1_4_spec.h"

static void
wire_header(uint8_t *bytes, uint16_t type, uint8_t flags, uint64_t selector,
    uint32_t length)
{

	memset(bytes, 0, VIRTIO14_DEV_PART_HEADER_SIZE);
	le16enc(bytes, type);
	bytes[2] = flags;
	le64enc(bytes + 4, selector);
	le32enc(bytes + 12, length);
}

ATF_TC_WITHOUT_HEAD(literal_layout_and_iteration);
ATF_TC_BODY(literal_layout_and_iteration, tc)
{
	struct virtio_device_parts_iterator iterator;
	struct virtio_device_part part;
	uint8_t bytes[24 + 24 + 18 + 17], common[2], features[8], status;
	size_t used;

	le64enc(features, UINT64_C(0x123456789abcdef0));
	status = VIRTIO14_STATUS_ACKNOWLEDGE | VIRTIO14_STATUS_DRIVER |
	    VIRTIO14_STATUS_DRIVER_OK | VIRTIO14_STATUS_FEATURES_OK |
	    VIRTIO14_STATUS_SUSPEND;
	memset(common, 0, sizeof(common));
	memset(bytes, 0xcc, sizeof(bytes));
	used = 0;
	ATF_REQUIRE_EQ(virtio_device_part_append(bytes, sizeof(bytes), &used,
	    VIRTIO14_DEV_PART_DEV_FEATURES,
	    VIRTIO14_DEV_PART_F_OPTIONAL, 0, features, sizeof(features)), 0);
	ATF_REQUIRE_EQ(virtio_device_part_append(bytes, sizeof(bytes), &used,
	    VIRTIO14_DEV_PART_DRV_FEATURES, 0, 0, features,
	    sizeof(features)), 0);
	ATF_REQUIRE_EQ(virtio_device_part_append(bytes, sizeof(bytes), &used,
	    VIRTIO14_DEV_PART_PCI_COMMON_CFG, 0, 18, common,
	    sizeof(common)), 0);
	ATF_REQUIRE_EQ(virtio_device_part_append(bytes, sizeof(bytes), &used,
	    VIRTIO14_DEV_PART_DEVICE_STATUS, 0, 0, &status,
	    sizeof(status)), 0);
	ATF_CHECK_EQ(used, sizeof(bytes));

	ATF_CHECK_EQ(le16dec(bytes), VIRTIO14_DEV_PART_DEV_FEATURES);
	ATF_CHECK_EQ(bytes[2], VIRTIO14_DEV_PART_F_OPTIONAL);
	ATF_CHECK_EQ(bytes[3], 0);
	ATF_CHECK_EQ(le64dec(bytes + 4), 0);
	ATF_CHECK_EQ(le32dec(bytes + 12), sizeof(features));
	ATF_CHECK_EQ(le64dec(bytes + 16),
	    UINT64_C(0x123456789abcdef0));

	virtio_device_parts_iterator_init(&iterator, bytes, used);
	ATF_REQUIRE_EQ(virtio_device_parts_next(&iterator, &part), 0);
	ATF_CHECK_EQ(part.type, VIRTIO14_DEV_PART_DEV_FEATURES);
	ATF_CHECK_EQ(part.flags, VIRTIO14_DEV_PART_F_OPTIONAL);
	ATF_CHECK_EQ(part.selector, 0);
	ATF_CHECK_EQ(part.length, sizeof(features));
	ATF_CHECK_EQ(le64dec(part.value),
	    UINT64_C(0x123456789abcdef0));
	ATF_REQUIRE_EQ(virtio_device_parts_next(&iterator, &part), 0);
	ATF_CHECK_EQ(part.type, VIRTIO14_DEV_PART_DRV_FEATURES);
	ATF_REQUIRE_EQ(virtio_device_parts_next(&iterator, &part), 0);
	ATF_CHECK_EQ(part.type, VIRTIO14_DEV_PART_PCI_COMMON_CFG);
	ATF_REQUIRE_EQ(virtio_device_parts_next(&iterator, &part), 0);
	ATF_CHECK_EQ(part.type, VIRTIO14_DEV_PART_DEVICE_STATUS);
	ATF_CHECK_EQ(part.length, 1);
	ATF_CHECK_EQ(part.value[0], status);
	ATF_CHECK_EQ(virtio_device_parts_next(&iterator, &part), ENOENT);
}

ATF_TC_WITHOUT_HEAD(selector_layouts);
ATF_TC_BODY(selector_layouts, tc)
{
	struct virtio_device_parts_iterator iterator;
	struct virtio_device_part part;
	uint8_t bytes[24 + 24 + 20 + 17 + 48 + 24];
	uint8_t common[2], features[8], queue[32], notify[8], status;
	size_t used;

	memset(common, 0x12, sizeof(common));
	memset(features, 0, sizeof(features));
	memset(queue, 0, sizeof(queue));
	memset(notify, 0, sizeof(notify));
	status = 4;
	used = 0;
	ATF_REQUIRE_EQ(virtio_device_part_append(bytes, sizeof(bytes), &used,
	    VIRTIO14_DEV_PART_DEV_FEATURES,
	    VIRTIO14_DEV_PART_F_OPTIONAL, 0, features,
	    sizeof(features)), 0);
	ATF_REQUIRE_EQ(virtio_device_part_append(bytes, sizeof(bytes), &used,
	    VIRTIO14_DEV_PART_DRV_FEATURES, 0, 0, features,
	    sizeof(features)), 0);
	ATF_REQUIRE_EQ(virtio_device_part_append(bytes, sizeof(bytes), &used,
	    VIRTIO14_DEV_PART_PCI_COMMON_CFG, 0, 18, common,
	    sizeof(common)), 0);
	ATF_REQUIRE_EQ(virtio_device_part_append(bytes, sizeof(bytes), &used,
	    VIRTIO14_DEV_PART_DEVICE_STATUS, 0, 0, &status,
	    sizeof(status)), 0);
	ATF_REQUIRE_EQ(virtio_device_part_append(bytes, sizeof(bytes), &used,
	    VIRTIO14_DEV_PART_VQ_CFG, 0, 7, queue, sizeof(queue)), 0);
	ATF_REQUIRE_EQ(virtio_device_part_append(bytes, sizeof(bytes), &used,
	    VIRTIO14_DEV_PART_VQ_NOTIFY_CFG, 0, 7, notify,
	    sizeof(notify)), 0);
	ATF_CHECK_EQ(le32dec(bytes + 24 + 24 + 4), 18);
	ATF_CHECK_EQ(le32dec(bytes + 24 + 24 + 8), 0);
	ATF_CHECK_EQ(le16dec(bytes + 24 + 24 + 18 + 17 + 4), 7);

	virtio_device_parts_iterator_init(&iterator, bytes, used);
	ATF_REQUIRE_EQ(virtio_device_parts_next(&iterator, &part), 0);
	ATF_REQUIRE_EQ(virtio_device_parts_next(&iterator, &part), 0);
	ATF_REQUIRE_EQ(virtio_device_parts_next(&iterator, &part), 0);
	ATF_CHECK_EQ(part.selector, 18);
	ATF_REQUIRE_EQ(virtio_device_parts_next(&iterator, &part), 0);
	ATF_REQUIRE_EQ(virtio_device_parts_next(&iterator, &part), 0);
	ATF_CHECK_EQ(part.selector, 7);
	ATF_REQUIRE_EQ(virtio_device_parts_next(&iterator, &part), 0);
	ATF_CHECK_EQ(part.selector, 7);
	ATF_CHECK_EQ(virtio_device_parts_next(&iterator, &part), ENOENT);
}

ATF_TC_WITHOUT_HEAD(metadata_header_list);
ATF_TC_BODY(metadata_header_list, tc)
{
	struct virtio_device_parts_iterator iterator;
	struct virtio_device_part part;
	uint8_t bytes[4 * VIRTIO14_DEV_PART_HEADER_SIZE], before[sizeof(bytes)];
	size_t used;

	memset(bytes, 0xa5, sizeof(bytes));
	used = 0;
	ATF_REQUIRE_EQ(virtio_device_part_header_append(bytes, sizeof(bytes),
	    &used, VIRTIO14_DEV_PART_DEV_FEATURES,
	    VIRTIO14_DEV_PART_F_OPTIONAL, 0, 8), 0);
	ATF_REQUIRE_EQ(virtio_device_part_header_append(bytes, sizeof(bytes),
	    &used, VIRTIO14_DEV_PART_DRV_FEATURES, 0, 0, 8), 0);
	ATF_REQUIRE_EQ(virtio_device_part_header_append(bytes, sizeof(bytes),
	    &used, VIRTIO14_DEV_PART_PCI_COMMON_CFG, 0, 18, 2), 0);
	ATF_REQUIRE_EQ(virtio_device_part_header_append(bytes, sizeof(bytes),
	    &used, VIRTIO14_DEV_PART_DEVICE_STATUS, 0, 0, 1), 0);
	ATF_CHECK_EQ(used, sizeof(bytes));

	virtio_device_part_headers_iterator_init(&iterator, bytes, used);
	ATF_REQUIRE_EQ(virtio_device_parts_next(&iterator, &part), 0);
	ATF_CHECK_EQ(part.type, VIRTIO14_DEV_PART_DEV_FEATURES);
	ATF_CHECK(part.value == NULL);
	ATF_CHECK_EQ(part.length, 8);
	ATF_REQUIRE_EQ(virtio_device_parts_next(&iterator, &part), 0);
	ATF_CHECK_EQ(part.type, VIRTIO14_DEV_PART_DRV_FEATURES);
	ATF_REQUIRE_EQ(virtio_device_parts_next(&iterator, &part), 0);
	ATF_CHECK_EQ(part.type, VIRTIO14_DEV_PART_PCI_COMMON_CFG);
	ATF_CHECK_EQ(part.selector, 18);
	ATF_REQUIRE_EQ(virtio_device_parts_next(&iterator, &part), 0);
	ATF_CHECK_EQ(part.type, VIRTIO14_DEV_PART_DEVICE_STATUS);
	ATF_CHECK_EQ(virtio_device_parts_next(&iterator, &part), ENOENT);

	/* A GET-SELECTED request may name a later part without predecessors. */
	virtio_device_part_selection_iterator_init(&iterator,
	    bytes + 3 * VIRTIO14_DEV_PART_HEADER_SIZE,
	    VIRTIO14_DEV_PART_HEADER_SIZE);
	ATF_REQUIRE_EQ(virtio_device_parts_next(&iterator, &part), 0);
	ATF_CHECK_EQ(part.type, VIRTIO14_DEV_PART_DEVICE_STATUS);
	ATF_CHECK_EQ(virtio_device_parts_next(&iterator, &part), ENOENT);

	virtio_device_part_headers_iterator_init(&iterator, bytes,
	    sizeof(bytes) - 1);
	ATF_REQUIRE_EQ(virtio_device_parts_next(&iterator, &part), 0);
	ATF_REQUIRE_EQ(virtio_device_parts_next(&iterator, &part), 0);
	ATF_REQUIRE_EQ(virtio_device_parts_next(&iterator, &part), 0);
	ATF_CHECK_EQ(virtio_device_parts_next(&iterator, &part), EPROTO);

	memcpy(before, bytes, sizeof(bytes));
	used = sizeof(bytes) - 1;
	ATF_CHECK_EQ(virtio_device_part_header_append(bytes, sizeof(bytes),
	    &used, VIRTIO14_DEV_PART_DEVICE_STATUS, 0, 0, 1), ENOSPC);
	ATF_CHECK_EQ(used, sizeof(bytes) - 1);
	ATF_CHECK_EQ(memcmp(bytes, before, sizeof(bytes)), 0);
}

static int
decode_one(uint8_t *bytes, size_t length)
{
	struct virtio_device_parts_iterator iterator;
	struct virtio_device_part part;

	virtio_device_parts_iterator_init(&iterator, bytes, length);
	return (virtio_device_parts_next(&iterator, &part));
}

ATF_TC_WITHOUT_HEAD(malformed_headers_and_values);
ATF_TC_BODY(malformed_headers_and_values, tc)
{
	uint8_t bytes[72];

	memset(bytes, 0, sizeof(bytes));
	ATF_CHECK_EQ(decode_one(bytes, 15), EPROTO);

	wire_header(bytes, VIRTIO14_DEV_PART_DEV_FEATURES,
	    VIRTIO14_DEV_PART_F_OPTIONAL, 0, 8);
	ATF_CHECK_EQ(decode_one(bytes, 23), EPROTO);
	bytes[2] = 0x80;
	ATF_CHECK_EQ(decode_one(bytes, 24), EPROTO);
	bytes[2] = VIRTIO14_DEV_PART_F_OPTIONAL;
	bytes[3] = 1;
	ATF_CHECK_EQ(decode_one(bytes, 24), EPROTO);
	bytes[3] = 0;
	le64enc(bytes + 4, 1);
	ATF_CHECK_EQ(decode_one(bytes, 24), EPROTO);
	le64enc(bytes + 4, 0);
	le32enc(bytes + 12, 7);
	ATF_CHECK_EQ(decode_one(bytes, 23), EPROTO);

	wire_header(bytes, VIRTIO14_DEV_PART_DEV_FEATURES, 0, 0, 8);
	ATF_CHECK_EQ(decode_one(bytes, 24), EPROTO);
	wire_header(bytes, VIRTIO14_DEV_PART_VQ_CFG, 0, 2, 32);
	bytes[16 + 6] = 1;
	ATF_CHECK_EQ(decode_one(bytes, sizeof(bytes)), EPROTO);
	wire_header(bytes, VIRTIO14_DEV_PART_VQ_NOTIFY_CFG, 0, 2, 8);
	bytes[16 + 4] = 1;
	ATF_CHECK_EQ(decode_one(bytes, 24), EPROTO);

	wire_header(bytes, VIRTIO14_DEV_PART_DEVICE_STATUS, 0, 0, 1);
	bytes[16] = 0x20;
	ATF_CHECK_EQ(decode_one(bytes, 17), EPROTO);
	wire_header(bytes, VIRTIO14_DEV_PART_VQ_CFG, 0, 2, 32);
	memset(bytes + 16, 0, 32);
	le16enc(bytes + 16 + 4, 2);
	ATF_CHECK_EQ(decode_one(bytes, 48), EPROTO);
}

ATF_TC_WITHOUT_HEAD(pci_common_field_widths);
ATF_TC_BODY(pci_common_field_widths, tc)
{
	static const struct {
		uint32_t offset;
		uint32_t length;
	} fields[] = {
		{ 0, 4 }, { 4, 4 }, { 8, 4 }, { 12, 4 },
		{ 16, 2 }, { 18, 2 }, { 20, 1 }, { 21, 1 },
		{ 22, 2 }, { 24, 2 }, { 26, 2 }, { 28, 2 },
		{ 30, 2 }, { 32, 4 }, { 36, 4 }, { 40, 4 },
		{ 44, 4 }, { 48, 4 }, { 52, 4 }, { 56, 2 },
		{ 58, 2 }, { 60, 2 }, { 62, 2 },
	};
	struct virtio_device_parts_iterator iterator;
	struct virtio_device_part part;
	uint8_t bytes[72], features[8], value[8];
	size_t used;

	memset(features, 0, sizeof(features));
	memset(value, 0, sizeof(value));
	for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
		used = 0;
		ATF_REQUIRE_EQ(virtio_device_part_append(bytes, sizeof(bytes),
		    &used, VIRTIO14_DEV_PART_DEV_FEATURES,
		    VIRTIO14_DEV_PART_F_OPTIONAL, 0, features,
		    sizeof(features)), 0);
		ATF_REQUIRE_EQ(virtio_device_part_append(bytes, sizeof(bytes),
		    &used, VIRTIO14_DEV_PART_DRV_FEATURES, 0, 0, features,
		    sizeof(features)), 0);
		ATF_CHECK_EQ(virtio_device_part_append(bytes, sizeof(bytes),
		    &used, VIRTIO14_DEV_PART_PCI_COMMON_CFG, 0,
		    fields[i].offset, value, fields[i].length), 0);
		ATF_CHECK_EQ(used, 2 * (VIRTIO14_DEV_PART_HEADER_SIZE +
		    sizeof(features)) + VIRTIO14_DEV_PART_HEADER_SIZE +
		    fields[i].length);
		virtio_device_parts_iterator_init(&iterator, bytes, used);
		ATF_REQUIRE_EQ(virtio_device_parts_next(&iterator, &part), 0);
		ATF_REQUIRE_EQ(virtio_device_parts_next(&iterator, &part), 0);
		ATF_REQUIRE_EQ(virtio_device_parts_next(&iterator, &part), 0);
		ATF_CHECK_EQ(part.selector, fields[i].offset);
		ATF_CHECK_EQ(part.length, fields[i].length);
		ATF_CHECK_EQ(virtio_device_parts_next(&iterator, &part),
		    ENOENT);

		used = 0;
		ATF_CHECK_EQ(virtio_device_part_append(bytes, sizeof(bytes),
		    &used, VIRTIO14_DEV_PART_PCI_COMMON_CFG, 0,
		    fields[i].offset, value,
		    fields[i].length == 1 ? 2 : 1), EINVAL);
	}
	used = 0;
	ATF_CHECK_EQ(virtio_device_part_append(bytes, sizeof(bytes), &used,
	    VIRTIO14_DEV_PART_PCI_COMMON_CFG, 0, 19, value, 1), EINVAL);
	wire_header(bytes, VIRTIO14_DEV_PART_PCI_COMMON_CFG, 0, 64, 2);
	ATF_CHECK_EQ(decode_one(bytes, 18), EPROTO);
}

ATF_TC_WITHOUT_HEAD(unknown_optional_and_order);
ATF_TC_BODY(unknown_optional_and_order, tc)
{
	struct virtio_device_parts_iterator iterator;
	struct virtio_device_part part;
	uint8_t bytes[72], features[8];
	size_t used;

	memset(bytes, 0, sizeof(bytes));
	wire_header(bytes, 0x0200, VIRTIO14_DEV_PART_F_OPTIONAL, 0, 0);
	ATF_CHECK_EQ(decode_one(bytes, 16), 0);
	bytes[2] = 0;
	ATF_CHECK_EQ(decode_one(bytes, 16), EOPNOTSUPP);

	memset(features, 0, sizeof(features));
	used = 0;
	ATF_REQUIRE_EQ(virtio_device_part_append(bytes, sizeof(bytes), &used,
	    VIRTIO14_DEV_PART_DEV_FEATURES,
	    VIRTIO14_DEV_PART_F_OPTIONAL, 0, features,
	    sizeof(features)), 0);
	ATF_REQUIRE_EQ(virtio_device_part_append(bytes, sizeof(bytes), &used,
	    VIRTIO14_DEV_PART_DRV_FEATURES, 0, 0, features,
	    sizeof(features)), 0);
	ATF_REQUIRE_EQ(virtio_device_part_append(bytes, sizeof(bytes), &used,
	    VIRTIO14_DEV_PART_DEV_FEATURES,
	    VIRTIO14_DEV_PART_F_OPTIONAL, 0, features,
	    sizeof(features)), 0);
	virtio_device_parts_iterator_init(&iterator, bytes, used);
	ATF_REQUIRE_EQ(virtio_device_parts_next(&iterator, &part), 0);
	ATF_REQUIRE_EQ(virtio_device_parts_next(&iterator, &part), 0);
	ATF_CHECK_EQ(virtio_device_parts_next(&iterator, &part), EPROTO);

	wire_header(bytes, VIRTIO14_DEV_PART_DEVICE_STATUS, 0, 0, 1);
	bytes[16] = 4;
	ATF_CHECK_EQ(decode_one(bytes, 17), EPROTO);
}

ATF_TC_WITHOUT_HEAD(repeated_selectors_rejected);
ATF_TC_BODY(repeated_selectors_rejected, tc)
{
	struct virtio_device_parts_iterator iterator;
	struct virtio_device_part part;
	uint8_t bytes[84], features[8], value[2];
	size_t used;

	memset(value, 0, sizeof(value));
	memset(features, 0, sizeof(features));
	used = 0;
	ATF_REQUIRE_EQ(virtio_device_part_append(bytes, sizeof(bytes), &used,
	    VIRTIO14_DEV_PART_DEV_FEATURES,
	    VIRTIO14_DEV_PART_F_OPTIONAL, 0, features,
	    sizeof(features)), 0);
	ATF_REQUIRE_EQ(virtio_device_part_append(bytes, sizeof(bytes), &used,
	    VIRTIO14_DEV_PART_DRV_FEATURES, 0, 0, features,
	    sizeof(features)), 0);
	ATF_REQUIRE_EQ(virtio_device_part_append(bytes, sizeof(bytes), &used,
	    VIRTIO14_DEV_PART_PCI_COMMON_CFG, 0, 18, value,
	    sizeof(value)), 0);
	ATF_REQUIRE_EQ(virtio_device_part_append(bytes, sizeof(bytes), &used,
	    VIRTIO14_DEV_PART_PCI_COMMON_CFG, 0, 18, value,
	    sizeof(value)), 0);
	virtio_device_parts_iterator_init(&iterator, bytes, used);
	ATF_REQUIRE_EQ(virtio_device_parts_next(&iterator, &part), 0);
	ATF_REQUIRE_EQ(virtio_device_parts_next(&iterator, &part), 0);
	ATF_REQUIRE_EQ(virtio_device_parts_next(&iterator, &part), 0);
	ATF_CHECK_EQ(virtio_device_parts_next(&iterator, &part), EPROTO);
}

ATF_TC_WITHOUT_HEAD(append_is_bounded_and_atomic);
ATF_TC_BODY(append_is_bounded_and_atomic, tc)
{
	union {
		max_align_t alignment;
		uint8_t bytes[24];
	} aliased_cursor;
	uint8_t bytes[24], before[24], status, value[8];
	size_t *cursor, used;

	memset(bytes, 0xa5, sizeof(bytes));
	memcpy(before, bytes, sizeof(bytes));
	memset(value, 0, sizeof(value));
	used = 1;
	ATF_CHECK_EQ(virtio_device_part_append(bytes, sizeof(bytes), &used,
	    VIRTIO14_DEV_PART_DEV_FEATURES,
	    VIRTIO14_DEV_PART_F_OPTIONAL, 0, value, sizeof(value)), ENOSPC);
	ATF_CHECK_EQ(used, 1);
	ATF_CHECK_EQ(memcmp(bytes, before, sizeof(bytes)), 0);
	used = 0;
	ATF_CHECK_EQ(virtio_device_part_append(bytes, sizeof(bytes), &used,
	    0x0200, VIRTIO14_DEV_PART_F_OPTIONAL, 0, NULL, 0),
	    EOPNOTSUPP);
	ATF_CHECK_EQ(used, 0);
	ATF_CHECK_EQ(memcmp(bytes, before, sizeof(bytes)), 0);
	ATF_CHECK_EQ(virtio_device_part_append(bytes, sizeof(bytes), &used,
	    VIRTIO14_DEV_PART_VQ_CFG, 0, UINT16_MAX + UINT64_C(1), value,
	    sizeof(value)), ERANGE);
	ATF_CHECK_EQ(used, 0);
	ATF_CHECK_EQ(virtio_device_part_header_append(bytes, sizeof(bytes),
	    &used, VIRTIO14_DEV_PART_PCI_COMMON_CFG, 0,
	    UINT32_MAX + UINT64_C(1), 2), ERANGE);
	ATF_CHECK_EQ(used, 0);
	status = 0x20;
	ATF_CHECK_EQ(virtio_device_part_append(bytes, sizeof(bytes), &used,
	    VIRTIO14_DEV_PART_DEVICE_STATUS, 0, 0, &status,
	    sizeof(status)), EINVAL);
	ATF_CHECK_EQ(used, 0);

	/* Header-first publication must not corrupt an aliased value source. */
	memset(bytes, 0x5a, sizeof(bytes));
	memcpy(before, bytes, sizeof(bytes));
	used = 0;
	ATF_CHECK_EQ(virtio_device_part_append(bytes, sizeof(bytes), &used,
	    VIRTIO14_DEV_PART_DEV_FEATURES,
	    VIRTIO14_DEV_PART_F_OPTIONAL, 0, bytes + 8, sizeof(value)),
	    EINVAL);
	ATF_CHECK_EQ(used, 0);
	ATF_CHECK_EQ(memcmp(bytes, before, sizeof(bytes)), 0);

	/* The public header builder must likewise reject a cursor in its output. */
	memset(aliased_cursor.bytes, 0x3c, sizeof(aliased_cursor.bytes));
	cursor = (size_t *)(void *)aliased_cursor.bytes;
	*cursor = 0;
	memcpy(before, aliased_cursor.bytes, sizeof(before));
	ATF_CHECK_EQ(virtio_device_part_header_append(aliased_cursor.bytes,
	    sizeof(aliased_cursor.bytes), cursor,
	    VIRTIO14_DEV_PART_DEV_FEATURES,
	    VIRTIO14_DEV_PART_F_OPTIONAL, 0, sizeof(value)), EINVAL);
	ATF_CHECK_EQ(*cursor, 0);
	ATF_CHECK_EQ(memcmp(aliased_cursor.bytes, before, sizeof(before)), 0);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, literal_layout_and_iteration);
	ATF_TP_ADD_TC(tp, selector_layouts);
	ATF_TP_ADD_TC(tp, metadata_header_list);
	ATF_TP_ADD_TC(tp, malformed_headers_and_values);
	ATF_TP_ADD_TC(tp, pci_common_field_widths);
	ATF_TP_ADD_TC(tp, unknown_optional_and_order);
	ATF_TP_ADD_TC(tp, repeated_selectors_rejected);
	ATF_TP_ADD_TC(tp, append_is_bounded_and_atomic);
	return (atf_no_error());
}
