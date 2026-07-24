/* Tests for transport-independent FreeBSD guest VirtIO contracts. */
#include <sys/types.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include <dev/virtio/mmio/virtio_mmio.h>
#include <dev/virtio/pci/virtio_pci_modern_var.h>
#include <dev/virtio/pci/virtio_pci_var.h>
#include <dev/virtio/virtio_ids.h>
#include <dev/virtio/virtio.h>

#include "virtio_1_4_spec.h"
#include "virtio_1_4_wire.h"

ATF_TC_WITHOUT_HEAD(virtio_1_4_wire_constants);
ATF_TC_BODY(virtio_1_4_wire_constants, tc)
{

	ATF_CHECK_EQ(VIRTIO_CONFIG_STATUS_ACK,
	    VIRTIO14_STATUS_ACKNOWLEDGE);
	ATF_CHECK_EQ(VIRTIO_CONFIG_STATUS_DRIVER, VIRTIO14_STATUS_DRIVER);
	ATF_CHECK_EQ(VIRTIO_CONFIG_STATUS_DRIVER_OK,
	    VIRTIO14_STATUS_DRIVER_OK);
	ATF_CHECK_EQ(VIRTIO_CONFIG_S_FEATURES_OK,
	    VIRTIO14_STATUS_FEATURES_OK);
	ATF_CHECK_EQ(VIRTIO_CONFIG_S_NEEDS_RESET,
	    VIRTIO14_STATUS_DEVICE_NEEDS_RESET);
	ATF_CHECK_EQ(VIRTIO_CONFIG_STATUS_FAILED, VIRTIO14_STATUS_FAILED);

	ATF_CHECK_EQ(VIRTIO_RING_F_INDIRECT_DESC,
	    VIRTIO14_F_RING_INDIRECT_DESC);
	ATF_CHECK_EQ(VIRTIO_RING_F_EVENT_IDX, VIRTIO14_F_RING_EVENT_IDX);
	ATF_CHECK_EQ(VIRTIO_F_VERSION_1, VIRTIO14_F_VERSION_1);
	ATF_CHECK_EQ(VIRTIO_F_ACCESS_PLATFORM,
	    VIRTIO14_F_ACCESS_PLATFORM);
	ATF_CHECK_EQ(VIRTIO_F_RING_PACKED, VIRTIO14_F_RING_PACKED);
	ATF_CHECK_EQ(VIRTIO_F_IN_ORDER, VIRTIO14_F_IN_ORDER);
	ATF_CHECK_EQ(VIRTIO_F_ORDER_PLATFORM, VIRTIO14_F_ORDER_PLATFORM);
	ATF_CHECK_EQ(VIRTIO_F_SR_IOV, VIRTIO14_F_SR_IOV);
	ATF_CHECK_EQ(VIRTIO_F_NOTIFICATION_DATA,
	    VIRTIO14_F_NOTIFICATION_DATA);
	ATF_CHECK_EQ(VIRTIO_F_NOTIF_CONFIG_DATA,
	    VIRTIO14_F_NOTIF_CONFIG_DATA);
	ATF_CHECK_EQ(VIRTIO_F_RING_RESET, VIRTIO14_F_RING_RESET);
	ATF_CHECK_EQ(VIRTIO_F_ADMIN_VQ, VIRTIO14_F_ADMIN_VQ);
	ATF_CHECK_EQ(VIRTIO_F_SUSPEND, VIRTIO14_F_SUSPEND);

	ATF_CHECK_EQ(VIRTIO_ID_NETWORK, VIRTIO14_DEVICE_NETWORK);
	ATF_CHECK_EQ(VIRTIO_ID_BLOCK, VIRTIO14_DEVICE_BLOCK);
	ATF_CHECK_EQ(VIRTIO_ID_CONSOLE, VIRTIO14_DEVICE_CONSOLE);
	ATF_CHECK_EQ(VIRTIO_ID_ENTROPY, VIRTIO14_DEVICE_ENTROPY);
	ATF_CHECK_EQ(VIRTIO_ID_SCSI, VIRTIO14_DEVICE_SCSI);
	ATF_CHECK_EQ(VIRTIO_ID_9P, VIRTIO14_DEVICE_9P);
	ATF_CHECK_EQ(VIRTIO_ID_INPUT, VIRTIO14_DEVICE_INPUT);
	ATF_CHECK_EQ(VIRTIO_ID_VSOCK, VIRTIO14_DEVICE_VSOCK);

	ATF_CHECK_EQ(VIRTIO_PCI_CAP_COMMON_CFG,
	    VIRTIO14_PCI_CAP_COMMON_CFG);
	ATF_CHECK_EQ(VIRTIO_PCI_CAP_NOTIFY_CFG,
	    VIRTIO14_PCI_CAP_NOTIFY_CFG);
	ATF_CHECK_EQ(VIRTIO_PCI_CAP_ISR_CFG, VIRTIO14_PCI_CAP_ISR_CFG);
	ATF_CHECK_EQ(VIRTIO_PCI_CAP_DEVICE_CFG,
	    VIRTIO14_PCI_CAP_DEVICE_CFG);
	ATF_CHECK_EQ(VIRTIO_PCI_CAP_PCI_CFG, VIRTIO14_PCI_CAP_PCI_CFG);
	ATF_CHECK_EQ(VIRTIO_PCI_ISR_INTR, VIRTIO14_ISR_QUEUE);
	ATF_CHECK_EQ(VIRTIO_PCI_ISR_CONFIG, VIRTIO14_ISR_CONFIG);
	ATF_CHECK_EQ(VIRTIO_MSI_NO_VECTOR, VIRTIO14_MSI_NO_VECTOR);
}

ATF_TC_WITHOUT_HEAD(virtio_1_4_pci_layout);
ATF_TC_BODY(virtio_1_4_pci_layout, tc)
{

	ATF_CHECK_EQ(sizeof(struct virtio_pci_cap),
	    VIRTIO14_PCI_CAP_SIZE);
	ATF_CHECK_EQ(sizeof(struct virtio_pci_notify_cap),
	    VIRTIO14_PCI_NOTIFY_CAP_SIZE);
	ATF_CHECK_EQ(sizeof(struct virtio_pci_cfg_cap),
	    VIRTIO14_PCI_CFG_CAP_SIZE);
	ATF_CHECK_EQ(offsetof(struct virtio_pci_cap, cap_vndr),
	    VIRTIO14_PCI_CAP_VNDR_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_pci_cap, cap_next),
	    VIRTIO14_PCI_CAP_NEXT_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_pci_cap, cap_len),
	    VIRTIO14_PCI_CAP_LEN_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_pci_cap, cfg_type),
	    VIRTIO14_PCI_CAP_CFG_TYPE_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_pci_cap, bar),
	    VIRTIO14_PCI_CAP_BAR_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_pci_cap, offset),
	    VIRTIO14_PCI_CAP_OFFSET_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_pci_cap, length),
	    VIRTIO14_PCI_CAP_LENGTH_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_pci_notify_cap,
	    notify_off_multiplier), VIRTIO14_PCI_NOTIFY_MULT_OFF);

	ATF_CHECK_EQ(sizeof(struct virtio_pci_common_cfg),
	    VIRTIO14_COMMON_BASE_SIZE);
	ATF_CHECK_EQ(offsetof(struct virtio_pci_common_cfg,
	    device_feature_select), VIRTIO14_COMMON_DEVICE_FEATURE_SELECT);
	ATF_CHECK_EQ(offsetof(struct virtio_pci_common_cfg, device_feature),
	    VIRTIO14_COMMON_DEVICE_FEATURE);
	ATF_CHECK_EQ(offsetof(struct virtio_pci_common_cfg,
	    guest_feature_select), VIRTIO14_COMMON_DRIVER_FEATURE_SELECT);
	ATF_CHECK_EQ(offsetof(struct virtio_pci_common_cfg, guest_feature),
	    VIRTIO14_COMMON_DRIVER_FEATURE);
	ATF_CHECK_EQ(offsetof(struct virtio_pci_common_cfg, msix_config),
	    VIRTIO14_COMMON_CONFIG_MSIX_VECTOR);
	ATF_CHECK_EQ(offsetof(struct virtio_pci_common_cfg, num_queues),
	    VIRTIO14_COMMON_NUM_QUEUES);
	ATF_CHECK_EQ(offsetof(struct virtio_pci_common_cfg, device_status),
	    VIRTIO14_COMMON_DEVICE_STATUS);
	ATF_CHECK_EQ(offsetof(struct virtio_pci_common_cfg,
	    config_generation), VIRTIO14_COMMON_CONFIG_GENERATION);
	ATF_CHECK_EQ(offsetof(struct virtio_pci_common_cfg, queue_select),
	    VIRTIO14_COMMON_QUEUE_SELECT);
	ATF_CHECK_EQ(offsetof(struct virtio_pci_common_cfg, queue_size),
	    VIRTIO14_COMMON_QUEUE_SIZE);
	ATF_CHECK_EQ(offsetof(struct virtio_pci_common_cfg,
	    queue_msix_vector), VIRTIO14_COMMON_QUEUE_MSIX_VECTOR);
	ATF_CHECK_EQ(offsetof(struct virtio_pci_common_cfg, queue_enable),
	    VIRTIO14_COMMON_QUEUE_ENABLE);
	ATF_CHECK_EQ(offsetof(struct virtio_pci_common_cfg, queue_notify_off),
	    VIRTIO14_COMMON_QUEUE_NOTIFY_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_pci_common_cfg, queue_desc_lo),
	    VIRTIO14_COMMON_QUEUE_DESC);
	ATF_CHECK_EQ(offsetof(struct virtio_pci_common_cfg, queue_avail_lo),
	    VIRTIO14_COMMON_QUEUE_DRIVER);
	ATF_CHECK_EQ(offsetof(struct virtio_pci_common_cfg, queue_used_lo),
	    VIRTIO14_COMMON_QUEUE_DEVICE);
}

ATF_TC_WITHOUT_HEAD(virtio_1_4_mmio_layout);
ATF_TC_BODY(virtio_1_4_mmio_layout, tc)
{

	ATF_CHECK_EQ(VIRTIO_MMIO_MAGIC_VALUE, VIRTIO14_MMIO_MAGIC_VALUE);
	ATF_CHECK_EQ(VIRTIO_MMIO_VERSION, VIRTIO14_MMIO_VERSION);
	ATF_CHECK_EQ(VIRTIO_MMIO_DEVICE_ID, VIRTIO14_MMIO_DEVICE_ID);
	ATF_CHECK_EQ(VIRTIO_MMIO_VENDOR_ID, VIRTIO14_MMIO_VENDOR_ID);
	ATF_CHECK_EQ(VIRTIO_MMIO_HOST_FEATURES,
	    VIRTIO14_MMIO_DEVICE_FEATURES);
	ATF_CHECK_EQ(VIRTIO_MMIO_HOST_FEATURES_SEL,
	    VIRTIO14_MMIO_DEVICE_FEATURES_SEL);
	ATF_CHECK_EQ(VIRTIO_MMIO_GUEST_FEATURES,
	    VIRTIO14_MMIO_DRIVER_FEATURES);
	ATF_CHECK_EQ(VIRTIO_MMIO_GUEST_FEATURES_SEL,
	    VIRTIO14_MMIO_DRIVER_FEATURES_SEL);
	ATF_CHECK_EQ(VIRTIO_MMIO_QUEUE_SEL, VIRTIO14_MMIO_QUEUE_SEL);
	ATF_CHECK_EQ(VIRTIO_MMIO_QUEUE_NUM_MAX,
	    VIRTIO14_MMIO_QUEUE_NUM_MAX);
	ATF_CHECK_EQ(VIRTIO_MMIO_QUEUE_NUM, VIRTIO14_MMIO_QUEUE_NUM);
	ATF_CHECK_EQ(VIRTIO_MMIO_QUEUE_READY, VIRTIO14_MMIO_QUEUE_READY);
	ATF_CHECK_EQ(VIRTIO_MMIO_QUEUE_NOTIFY, VIRTIO14_MMIO_QUEUE_NOTIFY);
	ATF_CHECK_EQ(VIRTIO_MMIO_INTERRUPT_STATUS,
	    VIRTIO14_MMIO_INTERRUPT_STATUS);
	ATF_CHECK_EQ(VIRTIO_MMIO_INTERRUPT_ACK,
	    VIRTIO14_MMIO_INTERRUPT_ACK);
	ATF_CHECK_EQ(VIRTIO_MMIO_STATUS, VIRTIO14_MMIO_STATUS);
	ATF_CHECK_EQ(VIRTIO_MMIO_QUEUE_DESC_LOW,
	    VIRTIO14_MMIO_QUEUE_DESC_LOW);
	ATF_CHECK_EQ(VIRTIO_MMIO_QUEUE_DESC_HIGH,
	    VIRTIO14_MMIO_QUEUE_DESC_HIGH);
	ATF_CHECK_EQ(VIRTIO_MMIO_QUEUE_AVAIL_LOW,
	    VIRTIO14_MMIO_QUEUE_DRIVER_LOW);
	ATF_CHECK_EQ(VIRTIO_MMIO_QUEUE_AVAIL_HIGH,
	    VIRTIO14_MMIO_QUEUE_DRIVER_HIGH);
	ATF_CHECK_EQ(VIRTIO_MMIO_QUEUE_USED_LOW,
	    VIRTIO14_MMIO_QUEUE_DEVICE_LOW);
	ATF_CHECK_EQ(VIRTIO_MMIO_QUEUE_USED_HIGH,
	    VIRTIO14_MMIO_QUEUE_DEVICE_HIGH);
	ATF_CHECK_EQ(VIRTIO_MMIO_QUEUE_RESET, VIRTIO14_MMIO_QUEUE_RESET);
	ATF_CHECK_EQ(VIRTIO_MMIO_CONFIG_GENERATION,
	    VIRTIO14_MMIO_CONFIG_GENERATION);
	ATF_CHECK_EQ(VIRTIO_MMIO_CONFIG, VIRTIO14_MMIO_CONFIG);
	ATF_CHECK_EQ(VIRTIO_MMIO_MAGIC_VIRT, VIRTIO14_MMIO_MAGIC_VIRT);
	ATF_CHECK_EQ(VIRTIO_MMIO_INT_VRING,
	    VIRTIO14_MMIO_INTERRUPT_VRING);
	ATF_CHECK_EQ(VIRTIO_MMIO_INT_CONFIG,
	    VIRTIO14_MMIO_INTERRUPT_CONFIG);
}

ATF_TC_WITHOUT_HEAD(reinit_feature_ceiling);
ATF_TC_BODY(reinit_feature_ceiling, tc)
{
	const uint64_t original = VIRTIO14_NET_F_MTU |
	    VIRTIO14_NET_F_CTRL_VQ | VIRTIO14_F_IN_ORDER;
	uint64_t reduced;

	ATF_CHECK(virtio_features_subset(original, original));
	ATF_CHECK(virtio_features_subset(original, 0));

	reduced = original & ~VIRTIO14_NET_F_CTRL_VQ;
	ATF_CHECK(virtio_features_subset(original, reduced));

	/*
	 * A feature disabled by one reinitialization can be restored because
	 * the ceiling is the original negotiation, not the current subset.
	 */
	ATF_CHECK(virtio_features_subset(original, original));

	ATF_CHECK(!virtio_features_subset(original,
	    original | VIRTIO14_NET_F_GUEST_RSC6));
	ATF_CHECK(!virtio_features_subset(0, VIRTIO14_F_VERSION_1));

	/*
	 * Reinitialization must fail if the device no longer offers the
	 * complete requested subset; the API cannot report a reduced set.
	 */
	ATF_CHECK(!virtio_features_subset(reduced, original));
}

ATF_TC_WITHOUT_HEAD(notification_write_width);
ATF_TC_BODY(notification_write_width, tc)
{
	uint32_t expected;

	ATF_CHECK_EQ(virtio_pci_queue_notify_size(false),
	    VIRTIO14_PCI_NOTIFY_NO_DATA_SIZE);
	ATF_CHECK_EQ(virtio_pci_queue_notify_size(true),
	    VIRTIO14_PCI_NOTIFY_DATA_SIZE);
	ATF_CHECK_EQ(VIRTIO14_MMIO_CONTROL_ACCESS_SIZE,
	    VIRTIO14_CONFIG_FIELD_U32_SIZE);

	expected = (UINT32_C(0xa55a) <<
	    VIRTIO14_NOTIFICATION_NEXT_OFF_SHIFT) |
	    (UINT32_C(0x1234) & VIRTIO14_NOTIFICATION_VQ_INDEX_MASK);
	ATF_CHECK_EQ(virtio_split_notification_data(0x1234, 0xa55a),
	    expected);
}

ATF_TC_WITHOUT_HEAD(notification_feature_validation);
ATF_TC_BODY(notification_feature_validation, tc)
{
	const uint64_t unrelated = VIRTIO14_NET_F_MTU;

	/*
	 * Section 4.1.4.4 requires the 32-bit notification capability layout
	 * when NotificationData is negotiated.  The expected masks below use
	 * only the document oracle; in particular, a child-requested copy of
	 * the transport feature cannot survive an invalid layout.
	 */
	ATF_CHECK_EQ(virtio_modern_notification_data_features(
	    unrelated | VIRTIO14_F_NOTIFICATION_DATA,
	    VIRTIO14_F_NOTIFICATION_DATA, false), unrelated);
	ATF_CHECK_EQ(virtio_modern_notification_data_features(
	    unrelated, VIRTIO14_F_NOTIFICATION_DATA, true),
	    unrelated | VIRTIO14_F_NOTIFICATION_DATA);
	ATF_CHECK_EQ(virtio_modern_notification_data_features(
	    unrelated | VIRTIO14_F_NOTIFICATION_DATA, 0, true), unrelated);
}

ATF_TC_WITHOUT_HEAD(split_queue_size_limits);
ATF_TC_BODY(split_queue_size_limits, tc)
{

	ATF_CHECK_EQ(VIRTIO_SPLIT_QUEUE_SIZE_MAX,
	    VIRTIO14_SPLIT_QUEUE_SIZE_MAX);
	ATF_CHECK(!virtio_split_queue_size_valid(0));
	ATF_CHECK(virtio_split_queue_size_valid(1));
	ATF_CHECK(virtio_split_queue_size_valid(
	    VIRTIO14_SPLIT_QUEUE_SIZE_MAX));
	ATF_CHECK(!virtio_split_queue_size_valid(
	    VIRTIO14_SPLIT_QUEUE_SIZE_MAX - 1));
	ATF_CHECK(!virtio_split_queue_size_valid(
	    VIRTIO14_SPLIT_QUEUE_SIZE_MAX + 1));
	ATF_CHECK(!virtio_split_queue_size_valid(UINT32_MAX));
}

ATF_TC_WITHOUT_HEAD(transport_feature_filter);
ATF_TC_BODY(transport_feature_filter, tc)
{
	const uint64_t requested = VIRTIO14_F_RING_INDIRECT_DESC |
	    VIRTIO14_F_RING_EVENT_IDX | VIRTIO14_F_VERSION_1 |
	    VIRTIO14_F_NOTIFY_ON_EMPTY | VIRTIO14_F_ANY_LAYOUT |
	    VIRTIO14_F_RESERVED_25 | VIRTIO14_F_RESERVED_26 |
	    VIRTIO14_F_IN_ORDER | VIRTIO14_F_ORDER_PLATFORM |
	    VIRTIO14_F_NOTIFICATION_DATA | VIRTIO14_F_NOTIF_CONFIG_DATA |
	    VIRTIO14_F_RING_RESET | VIRTIO14_F_ADMIN_VQ |
	    VIRTIO14_NET_F_GUEST_RSC6 | VIRTIO14_F_SUSPEND |
	    VIRTIO14_F_RESERVED_44 | VIRTIO14_F_RESERVED_49 |
	    VIRTIO14_NET_F_MTU | VIRTIO14_DEVICE_FEATURE_HIGH_FIRST;
	const uint64_t legacy_neutral_expected =
	    VIRTIO14_F_NOTIFY_ON_EMPTY | VIRTIO14_F_ANY_LAYOUT |
	    VIRTIO14_F_RING_INDIRECT_DESC |
	    VIRTIO14_F_RING_EVENT_IDX | VIRTIO14_F_VERSION_1 |
	    VIRTIO14_F_IN_ORDER | VIRTIO14_F_NOTIFICATION_DATA |
	    VIRTIO14_F_RING_RESET | VIRTIO14_F_ADMIN_VQ |
	    VIRTIO14_NET_F_GUEST_RSC6 | VIRTIO14_NET_F_MTU |
	    VIRTIO14_DEVICE_FEATURE_HIGH_FIRST;
	const uint64_t modern_expected = legacy_neutral_expected &
	    ~(VIRTIO14_F_NOTIFY_ON_EMPTY | VIRTIO14_F_ANY_LAYOUT |
	    VIRTIO14_F_ADMIN_VQ | VIRTIO14_NET_F_GUEST_RSC6);

	/*
	 * These legacy-only assignments drive the transport policy below.
	 * Compare the public constants directly with the document oracle so a
	 * production renumbering cannot make the filtering test self-confirm.
	 */
	ATF_CHECK_EQ((uint64_t)VIRTIO_F_NOTIFY_ON_EMPTY,
	    VIRTIO14_F_NOTIFY_ON_EMPTY);
	ATF_CHECK_EQ((uint64_t)VIRTIO_F_ANY_LAYOUT,
	    VIRTIO14_F_ANY_LAYOUT);
	ATF_CHECK_EQ(virtio_supported_transport_features(requested),
	    legacy_neutral_expected);
	ATF_CHECK_EQ(virtio_modern_supported_transport_features(requested),
	    modern_expected);
	ATF_CHECK_EQ(virtio_mmio_supported_transport_features(
	    VIRTIO14_MMIO_MODERN_VERSION, requested), modern_expected);
	ATF_CHECK_EQ(virtio_mmio_supported_transport_features(
	    VIRTIO14_MMIO_LEGACY_VERSION, requested),
	    legacy_neutral_expected & ~VIRTIO14_F_RING_RESET);
}

ATF_TC_WITHOUT_HEAD(device_config_ranges);
ATF_TC_BODY(device_config_ranges, tc)
{

	ATF_CHECK(virtio_config_range_valid(16, 0,
	    VIRTIO14_CONFIG_FIELD_U8_SIZE));
	ATF_CHECK(virtio_config_range_valid(16, 8,
	    VIRTIO14_CONFIG_FIELD_U64_SIZE));
	ATF_CHECK(virtio_config_range_valid(16, 16, 0));
	ATF_CHECK(!virtio_config_range_valid(0, 0, 1));
	ATF_CHECK(!virtio_config_range_valid(16, 16, 1));
	ATF_CHECK(!virtio_config_range_valid(16, 17, 0));
	ATF_CHECK(!virtio_config_range_valid(16, UINT64_MAX, 1));
	ATF_CHECK(!virtio_config_range_valid(UINT64_MAX, UINT64_MAX, 1));

	ATF_CHECK(virtio_modern_config_access_valid(16, 0,
	    VIRTIO14_CONFIG_FIELD_U8_SIZE));
	ATF_CHECK(virtio_modern_config_access_valid(16, 2,
	    VIRTIO14_CONFIG_FIELD_U16_SIZE));
	ATF_CHECK(virtio_modern_config_access_valid(16, 4,
	    VIRTIO14_CONFIG_FIELD_U32_SIZE));
	ATF_CHECK(virtio_modern_config_access_valid(16, 8,
	    VIRTIO14_CONFIG_FIELD_U64_SIZE));
	ATF_CHECK(!virtio_modern_config_access_valid(16, 1,
	    VIRTIO14_CONFIG_FIELD_U16_SIZE));
	ATF_CHECK(!virtio_modern_config_access_valid(16, 2,
	    VIRTIO14_CONFIG_FIELD_U32_SIZE));
	ATF_CHECK(!virtio_modern_config_access_valid(16, 2,
	    VIRTIO14_CONFIG_FIELD_U64_SIZE));
	ATF_CHECK(!virtio_modern_config_access_valid(16, 0, 3));
	ATF_CHECK(!virtio_modern_config_access_valid(16, 12,
	    VIRTIO14_CONFIG_FIELD_U64_SIZE));
}

ATF_TC_WITHOUT_HEAD(device_config_64bit_parts);
ATF_TC_BODY(device_config_64bit_parts, tc)
{
	const uint64_t value = UINT64_C(0x1122334455667788);
	uint8_t wire[8];
	uint32_t high, low;

	/*
	 * Inspect the bytes produced by the DUT with the independent wire
	 * decoder.  Decoding low and high with virtio_htog32() here would
	 * reuse the production endian primitive and let matching encode/decode
	 * defects self-confirm on a big-endian guest.
	 */
	virtio_config_write64_parts(true, value, &low, &high);
	ATF_CHECK_EQ(virtio14_load_le32((const uint8_t *)&low),
	    UINT32_C(0x55667788));
	ATF_CHECK_EQ(virtio14_load_le32((const uint8_t *)&high),
	    UINT32_C(0x11223344));
	ATF_CHECK_EQ(virtio_config_read64_parts(true, low, high), value);

	/*
	 * Feed the read helper independently assembled little-endian register
	 * values instead of feeding its paired write helper back to it.
	 */
	virtio14_store_le64(wire, value);
	memcpy(&low, &wire[0], sizeof(low));
	memcpy(&high, &wire[4], sizeof(high));
	ATF_CHECK_EQ(virtio_config_read64_parts(true, low, high), value);

	/* Legacy configuration halves remain in guest-native byte order. */
	virtio_config_write64_parts(false, value, &low, &high);
	ATF_CHECK_EQ(low, UINT32_C(0x55667788));
	ATF_CHECK_EQ(high, UINT32_C(0x11223344));
	ATF_CHECK_EQ(virtio_config_read64_parts(false, low, high), value);
}

ATF_TC_WITHOUT_HEAD(pci_capability_bar_ranges);
ATF_TC_BODY(pci_capability_bar_ranges, tc)
{

	ATF_CHECK(VIRTIO_PCI_CAP_BAR_VALID(VIRTIO14_PCI_MIN_BAR));
	ATF_CHECK(VIRTIO_PCI_CAP_BAR_VALID(VIRTIO14_PCI_MAX_BAR));
	ATF_CHECK(!VIRTIO_PCI_CAP_BAR_VALID(VIRTIO14_PCI_MAX_BAR + 1));
	ATF_CHECK(!VIRTIO_PCI_CAP_BAR_VALID(UINT8_MAX));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, reinit_feature_ceiling);
	ATF_TP_ADD_TC(tp, notification_write_width);
	ATF_TP_ADD_TC(tp, notification_feature_validation);
	ATF_TP_ADD_TC(tp, split_queue_size_limits);
	ATF_TP_ADD_TC(tp, transport_feature_filter);
	ATF_TP_ADD_TC(tp, device_config_ranges);
	ATF_TP_ADD_TC(tp, device_config_64bit_parts);
	ATF_TP_ADD_TC(tp, pci_capability_bar_ranges);
	ATF_TP_ADD_TC(tp, virtio_1_4_wire_constants);
	ATF_TP_ADD_TC(tp, virtio_1_4_pci_layout);
	ATF_TP_ADD_TC(tp, virtio_1_4_mmio_layout);

	return (atf_no_error());
}
