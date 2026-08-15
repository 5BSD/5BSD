#include <sys/types.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include "checkpoint_compat.c"
#include "pci_config_image.h"
#include "virtio_1_4_spec.h"

static void
make_compat(struct pci_snapshot_compat *compat)
{

	memset(compat, 0, sizeof(*compat));
	compat->schema = PCI_SNAPSHOT_COMPAT_SCHEMA;
	compat->transport = 1;
	compat->queue_count = 3;
	compat->msix_table_count = 4;
	compat->config_size = 64;
	compat->offered_features = UINT64_C(0x1122334455667788);
	compat->negotiated_features = UINT64_C(0x0102030405060708);
	compat->payload_crc32 = UINT32_C(0xa1b2c3d4);
	strlcpy(compat->queue_sizes, "256,256,32",
	    sizeof(compat->queue_sizes));
	strlcpy(compat->shared_memory, "1:4:4096:8192",
	    sizeof(compat->shared_memory));
}

ATF_TC_WITHOUT_HEAD(portable_round_trip);
ATF_TC_BODY(portable_round_trip, tc)
{
	struct pci_snapshot_compat decoded, source;
	uint8_t framed[CHECKPOINT_COMPAT_ENVELOPE_SIZE + 3];
	uint8_t record[CHECKPOINT_COMPAT_ENVELOPE_SIZE];

	make_compat(&source);
	memset(record, 0xa5, sizeof(record));
	ATF_REQUIRE_EQ(checkpoint_compat_encode(&source, record,
	    sizeof(record)), 0);
	ATF_CHECK_EQ(record[0], 0x31);
	ATF_CHECK_EQ(record[1], 0x43);
	ATF_CHECK_EQ(record[2], 0x56);
	ATF_CHECK_EQ(record[3], 0x42);
	ATF_CHECK_EQ(record[20], 64);
	ATF_CHECK_EQ(record[21], 0);
	ATF_CHECK_EQ(record[28], 0x88);
	ATF_CHECK_EQ(record[35], 0x11);
	ATF_CHECK_EQ(record[44], 0xd4);
	ATF_CHECK_EQ(record[47], 0xa1);
	ATF_REQUIRE_EQ(checkpoint_compat_decode(record, sizeof(record),
	    &decoded), 0);
	ATF_CHECK(checkpoint_compat_equal(&source, &decoded));

	/*
	 * The envelope prefixes the device-specific state in the snapshot
	 * record.  Decoding consumes only that fixed prefix; the coordinator
	 * separately checksums and validates every trailing payload byte.
	 */
	memcpy(framed, record, sizeof(record));
	memcpy(framed + sizeof(record), "dev", 3);
	ATF_REQUIRE_EQ(checkpoint_compat_decode(framed, sizeof(framed),
	    &decoded), 0);
	ATF_CHECK(checkpoint_compat_equal(&source, &decoded));
}

ATF_TC_WITHOUT_HEAD(payload_checksum_detects_mutation);
ATF_TC_BODY(payload_checksum_detects_mutation, tc)
{
	static const uint8_t canonical[] = "portable-device-state";
	uint8_t changed[sizeof(canonical)];
	uint32_t checksum;

	checksum = checkpoint_compat_payload_crc32(canonical,
	    sizeof(canonical));
	memcpy(changed, canonical, sizeof(changed));
	changed[7] ^= 1;
	ATF_CHECK(checksum != checkpoint_compat_payload_crc32(changed,
	    sizeof(changed)));
	ATF_CHECK_EQ(checkpoint_compat_payload_crc32(NULL, 0),
	    UINT32_C(0));
}

ATF_TC_WITHOUT_HEAD(rejects_malformed_envelope);
ATF_TC_BODY(rejects_malformed_envelope, tc)
{
	struct pci_snapshot_compat decoded, source;
	uint8_t record[CHECKPOINT_COMPAT_ENVELOPE_SIZE];

	make_compat(&source);
	ATF_REQUIRE_EQ(checkpoint_compat_encode(&source, record,
	    sizeof(record)), 0);
	ATF_CHECK_EQ(checkpoint_compat_decode(record, sizeof(record) - 1,
	    &decoded), EINVAL);
	record[0] ^= 1;
	ATF_CHECK_EQ(checkpoint_compat_decode(record, sizeof(record),
	    &decoded), EINVAL);
	record[0] ^= 1;
	memset(record + CHECKPOINT_COMPAT_SCALARS_SIZE, 'x',
	    PCI_SNAPSHOT_COMPAT_SHAPE_MAX);
	ATF_CHECK_EQ(checkpoint_compat_decode(record, sizeof(record),
	    &decoded), EINVAL);
	make_compat(&source);
	ATF_REQUIRE_EQ(checkpoint_compat_encode(&source, record,
	    sizeof(record)), 0);
	record[36] |= 0x02;
	ATF_CHECK_EQ(checkpoint_compat_decode(record, sizeof(record),
	    &decoded), EINVAL);
	make_compat(&source);
	ATF_REQUIRE_EQ(checkpoint_compat_encode(&source, record,
	    sizeof(record)), 0);
	record[CHECKPOINT_COMPAT_SCALARS_SIZE +
	    strlen(source.queue_sizes) + 1] = 1;
	ATF_CHECK_EQ(checkpoint_compat_decode(record, sizeof(record),
	    &decoded), EINVAL);
}

ATF_TC_WITHOUT_HEAD(rejects_noncanonical_source);
ATF_TC_BODY(rejects_noncanonical_source, tc)
{
	struct pci_snapshot_compat source;
	uint8_t record[CHECKPOINT_COMPAT_ENVELOPE_SIZE];

	make_compat(&source);
	source.schema++;
	ATF_CHECK_EQ(checkpoint_compat_encode(&source, record,
	    sizeof(record)), EINVAL);
	make_compat(&source);
	memset(source.shared_memory, 'x', sizeof(source.shared_memory));
	ATF_CHECK_EQ(checkpoint_compat_encode(&source, record,
	    sizeof(record)), EINVAL);
	make_compat(&source);
	source.queue_sizes[strlen(source.queue_sizes) + 1] = 1;
	ATF_CHECK_EQ(checkpoint_compat_encode(&source, record,
	    sizeof(record)), EINVAL);
	make_compat(&source);
	source.negotiated_features |= UINT64_C(0x02);
	ATF_CHECK_EQ(checkpoint_compat_encode(&source, record,
	    sizeof(record)), EINVAL);
	make_compat(&source);
	ATF_CHECK_EQ(checkpoint_compat_encode(&source, record,
	    sizeof(record) - 1), EINVAL);
}

ATF_TC_WITHOUT_HEAD(codec_is_transactional_and_overlap_safe);
ATF_TC_BODY(codec_is_transactional_and_overlap_safe, tc)
{
	union {
		struct pci_snapshot_compat compat;
		uint8_t record[CHECKPOINT_COMPAT_ENVELOPE_SIZE];
	} storage;
	struct pci_snapshot_compat before, decoded, source;
	uint8_t canonical[CHECKPOINT_COMPAT_ENVELOPE_SIZE];
	int error;

	make_compat(&source);
	ATF_REQUIRE_EQ(checkpoint_compat_encode(&source, canonical,
	    sizeof(canonical)), 0);

	memset(&decoded, 0xa5, sizeof(decoded));
	before = decoded;
	canonical[0] ^= 1;
	ATF_CHECK_EQ(checkpoint_compat_decode(canonical, sizeof(canonical),
	    &decoded), EINVAL);
	ATF_CHECK_EQ(memcmp(&decoded, &before, sizeof(decoded)), 0);
	canonical[0] ^= 1;

	storage.compat = source;
	ATF_REQUIRE_EQ(checkpoint_compat_encode(&storage.compat,
	    storage.record, sizeof(storage.record)), 0);
	ATF_CHECK_EQ(memcmp(storage.record, canonical, sizeof(canonical)), 0);

	memcpy(storage.record, canonical, sizeof(canonical));
	error = checkpoint_compat_decode(storage.record,
	    sizeof(storage.record), &storage.compat);
	ATF_REQUIRE_MSG(error == 0, "overlapping decode returned %d", error);
	ATF_CHECK(checkpoint_compat_equal(&storage.compat, &source));
	memset(storage.compat.queue_sizes, 'x',
	    sizeof(storage.compat.queue_sizes));
	ATF_CHECK(!checkpoint_compat_equal(&storage.compat, &source));
}

ATF_TC_WITHOUT_HEAD(pci_config_image_is_little_endian);
ATF_TC_BODY(pci_config_image_is_little_endian, tc)
{
	uint8_t image[9];

	memset(image, 0xa5, sizeof(image));
	pci_config_image_store8(image, 1, UINT8_C(0x7e));
	pci_config_image_store16(image, 2, UINT16_C(0x1234));
	pci_config_image_store32(image, 4, UINT32_C(0x89abcdef));
	ATF_CHECK_EQ(image[1], UINT8_C(0x7e));
	ATF_CHECK_EQ(image[2], UINT8_C(0x34));
	ATF_CHECK_EQ(image[3], UINT8_C(0x12));
	ATF_CHECK_EQ(image[4], UINT8_C(0xef));
	ATF_CHECK_EQ(image[5], UINT8_C(0xcd));
	ATF_CHECK_EQ(image[6], UINT8_C(0xab));
	ATF_CHECK_EQ(image[7], UINT8_C(0x89));
	ATF_CHECK_EQ(pci_config_image_load8(image, 1), UINT8_C(0x7e));
	ATF_CHECK_EQ(pci_config_image_load16(image, 2), UINT16_C(0x1234));
	ATF_CHECK_EQ(pci_config_image_load32(image, 4),
	    UINT32_C(0x89abcdef));

	/* The helpers must also accept an intentionally unaligned image. */
	pci_config_image_store32(image, 1, UINT32_C(0x10203040));
	ATF_CHECK_EQ(image[1], UINT8_C(0x40));
	ATF_CHECK_EQ(image[4], UINT8_C(0x10));
	ATF_CHECK_EQ(pci_config_image_load32(image, 1),
	    UINT32_C(0x10203040));
}

ATF_TC_WITHOUT_HEAD(restore_contract_negative_matrix);
ATF_TC_BODY(restore_contract_negative_matrix, tc)
{
	struct pci_snapshot_compat destination, source;

	memset(&source, 0, sizeof(source));
	source.schema = PCI_SNAPSHOT_COMPAT_SCHEMA;
	source.transport = 1;
	source.queue_count = 2;
	source.msix_table_count = 3;
	source.config_size = 64;
	/* Values come from the independent VirtIO 1.4 fixture. */
	source.offered_features = VIRTIO14_F_VERSION_1 |
	    VIRTIO14_F_ACCESS_PLATFORM;
	source.negotiated_features = VIRTIO14_F_ACCESS_PLATFORM;
	strlcpy(source.queue_sizes, "256,256",
	    sizeof(source.queue_sizes));
	strlcpy(source.shared_memory, "1:4:4096:8192",
	    sizeof(source.shared_memory));
	destination = source;
	ATF_REQUIRE_EQ(pci_snapshot_compat_validate(&source, &destination), 0);

	/* Translated DMA cannot silently become direct DMA after restore. */
	destination.offered_features &= ~VIRTIO14_F_ACCESS_PLATFORM;
	ATF_CHECK_EQ(pci_snapshot_compat_validate(&source, &destination),
	    ENOTSUP);

	destination = source;
	strlcpy(destination.queue_sizes, "128,256",
	    sizeof(destination.queue_sizes));
	ATF_CHECK_EQ(pci_snapshot_compat_validate(&source, &destination),
	    ENOTSUP);

	/*
	 * queue_count still delimits the ordinary prefix.  An administration
	 * queue range is carried by the canonical suffix as
	 * <selector-base>,<count>,<maximum sizes...>; moving that range must not
	 * be mistaken for an ordinary queue layout that happens to have the same
	 * prefix.
	 */
	strlcpy(source.queue_sizes, "256,256,5,2,16,32",
	    sizeof(source.queue_sizes));
	destination = source;
	strlcpy(destination.queue_sizes, "256,256,6,2,16,32",
	    sizeof(destination.queue_sizes));
	ATF_CHECK_EQ(pci_snapshot_compat_validate(&source, &destination),
	    ENOTSUP);

	destination = source;
	strlcpy(destination.shared_memory, "1:4:4096:4096",
	    sizeof(destination.shared_memory));
	ATF_CHECK_EQ(pci_snapshot_compat_validate(&source, &destination),
	    ENOTSUP);

	destination = source;
	source.negotiated_features |= VIRTIO14_F_RING_PACKED;
	ATF_CHECK_EQ(pci_snapshot_compat_validate(&source, &destination),
	    EINVAL);

	source = destination;
	destination.queue_sizes[strlen(destination.queue_sizes) + 1] = 1;
	ATF_CHECK_EQ(pci_snapshot_compat_validate(&source, &destination),
	    EINVAL);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, portable_round_trip);
	ATF_TP_ADD_TC(tp, payload_checksum_detects_mutation);
	ATF_TP_ADD_TC(tp, rejects_malformed_envelope);
	ATF_TP_ADD_TC(tp, rejects_noncanonical_source);
	ATF_TP_ADD_TC(tp, codec_is_transactional_and_overlap_safe);
	ATF_TP_ADD_TC(tp, pci_config_image_is_little_endian);
	ATF_TP_ADD_TC(tp, restore_contract_negative_matrix);
	return (atf_no_error());
}
