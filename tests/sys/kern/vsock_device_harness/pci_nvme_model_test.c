/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdint.h>

#include <atf-c.h>

#include "pci_nvme_model.h"

ATF_TC_WITHOUT_HEAD(doorbell_absolute_index);
ATF_TC_BODY(doorbell_absolute_index, tc)
{

	/* A wrapped absolute tail can exceed the number of free entries. */
	ATF_CHECK(pci_nvme_doorbell_value_valid(256, 250));
	ATF_CHECK(pci_nvme_doorbell_value_valid(256, 0));
	ATF_CHECK(pci_nvme_doorbell_value_valid(256, 255));
	ATF_CHECK(!pci_nvme_doorbell_value_valid(256, 256));
	ATF_CHECK(!pci_nvme_doorbell_value_valid(256, UINT64_MAX));
}

ATF_TC_WITHOUT_HEAD(doorbell_queue_boundaries);
ATF_TC_BODY(doorbell_queue_boundaries, tc)
{

	ATF_CHECK(!pci_nvme_doorbell_value_valid(0, 0));
	ATF_CHECK(pci_nvme_doorbell_value_valid(2, 0));
	ATF_CHECK(pci_nvme_doorbell_value_valid(2, 1));
	ATF_CHECK(!pci_nvme_doorbell_value_valid(2, 2));
	ATF_CHECK(pci_nvme_doorbell_value_valid(UINT16_MAX + 1U,
	    UINT16_MAX));
}

ATF_TC_WITHOUT_HEAD(mmio_access_boundaries);
ATF_TC_BODY(mmio_access_boundaries, tc)
{

	ATF_CHECK(pci_nvme_mmio_range_valid(0, 8, 4096));
	ATF_CHECK(pci_nvme_mmio_range_valid(4092, 4, 4096));
	ATF_CHECK(!pci_nvme_mmio_range_valid(4093, 4, 4096));
	ATF_CHECK(!pci_nvme_mmio_range_valid(4095, 8, 4096));
	ATF_CHECK(!pci_nvme_mmio_range_valid(UINT64_MAX, 4, 4096));
	ATF_CHECK(!pci_nvme_mmio_range_valid(0, 16, 4096));

	ATF_CHECK(pci_nvme_doorbell_access_valid(0, 4, 1));
	ATF_CHECK(pci_nvme_doorbell_access_valid(4, 4, 1));
	ATF_CHECK(pci_nvme_doorbell_access_valid(12, 4, 1));
	ATF_CHECK(!pci_nvme_doorbell_access_valid(16, 4, 1));
	ATF_CHECK(!pci_nvme_doorbell_access_valid(2, 4, 1));
	ATF_CHECK(!pci_nvme_doorbell_access_valid(0, 8, 1));
}

ATF_TC_WITHOUT_HEAD(prp_alignment_and_list_bounds);
ATF_TC_BODY(prp_alignment_and_list_bounds, tc)
{

	ATF_CHECK(pci_nvme_prp1_valid(UINT64_C(0x1004)));
	ATF_CHECK(!pci_nvme_prp1_valid(UINT64_C(0x1001)));
	ATF_CHECK(pci_nvme_queue_base_valid(UINT64_C(0x1000), 4096));
	ATF_CHECK(!pci_nvme_queue_base_valid(UINT64_C(0x1004), 4096));
	ATF_CHECK(!pci_nvme_queue_base_valid(UINT64_C(0x1000), 0));
	ATF_CHECK(!pci_nvme_queue_base_valid(UINT64_C(0x1000), 3072));
	ATF_CHECK(pci_nvme_log_offset_valid(0));
	ATF_CHECK(pci_nvme_log_offset_valid(UINT64_C(0x100000004)));
	ATF_CHECK(!pci_nvme_log_offset_valid(1));
	ATF_CHECK(!pci_nvme_log_offset_valid(UINT64_C(0x100000002)));
	ATF_CHECK(pci_nvme_prp2_valid(UINT64_C(0x2000), 4096, 4096));
	ATF_CHECK(!pci_nvme_prp2_valid(UINT64_C(0x2008), 4096, 4096));
	ATF_CHECK(pci_nvme_prp2_valid(UINT64_C(0x2ff8), 8192, 4096));
	ATF_CHECK(!pci_nvme_prp2_valid(UINT64_C(0x2ffc), 8192, 4096));
	ATF_CHECK_EQ(pci_nvme_prp_list_bytes(UINT64_C(0x2000), 4096),
	    4096U);
	ATF_CHECK_EQ(pci_nvme_prp_list_bytes(UINT64_C(0x2ff8), 4096), 8U);
	ATF_CHECK_EQ(pci_nvme_prp_list_bytes(UINT64_C(0x2ffc), 4096), 0U);
	ATF_CHECK_EQ(pci_nvme_prp_list_bytes(UINT64_C(0x2000), 3000), 0U);
}

ATF_TC_WITHOUT_HEAD(ram_command_direction);
ATF_TC_BODY(ram_command_direction, tc)
{

	ATF_CHECK(!pci_nvme_command_copies_to_guest(true));
	ATF_CHECK(pci_nvme_command_copies_to_guest(false));
}

ATF_TC_WITHOUT_HEAD(dsm_transfer_length);
ATF_TC_BODY(dsm_transfer_length, tc)
{

	ATF_CHECK_EQ(pci_nvme_dsm_range_bytes(0), 16U);
	ATF_CHECK_EQ(pci_nvme_dsm_range_bytes(1), 32U);
	ATF_CHECK_EQ(pci_nvme_dsm_range_bytes(UINT8_MAX), 4096U);
}

ATF_TC_WITHOUT_HEAD(dsm_skips_leading_empty_range);
ATF_TC_BODY(dsm_skips_leading_empty_range, tc)
{
	uint64_t offset;
	size_t length;

	/* The compacted first entry originated at source descriptor one. */
	ATF_REQUIRE(pci_nvme_dsm_cursor_initialize(1,
	    UINT64_C(0x4000), 8192, &offset, &length));
	ATF_CHECK_EQ(offset, UINT64_C(0x4000));
	ATF_CHECK_EQ(length, 8192U);
	ATF_CHECK(!pci_nvme_dsm_cursor_initialize(0,
	    UINT64_C(0x4000), 8192, &offset, &length));
	ATF_CHECK(!pci_nvme_dsm_cursor_initialize(1,
	    UINT64_C(0x4000), 0, &offset, &length));
}

ATF_TC_WITHOUT_HEAD(completion_phase_is_device_owned);
ATF_TC_BODY(completion_phase_is_device_owned, tc)
{
	bool wrapped;
	uint32_t index;

	ATF_CHECK_EQ(pci_nvme_status_with_phase(UINT16_C(0x1234), true),
	    UINT16_C(0x1235));
	ATF_CHECK_EQ(pci_nvme_status_with_phase(UINT16_C(0x1235), false),
	    UINT16_C(0x1234));
	index = pci_nvme_ring_advance(2, 4, &wrapped);
	ATF_CHECK_EQ(index, 3U);
	ATF_CHECK(!wrapped);
	index = pci_nvme_ring_advance(index, 4, &wrapped);
	ATF_CHECK_EQ(index, 0U);
	ATF_CHECK(wrapped);
}

ATF_TC_WITHOUT_HEAD(completion_queue_backpressure);
ATF_TC_BODY(completion_queue_backpressure, tc)
{

	ATF_CHECK(!pci_nvme_completion_queue_full(0, 0, 4));
	ATF_CHECK(pci_nvme_completion_queue_full(0, 3, 4));
	ATF_CHECK(pci_nvme_completion_queue_full(2, 1, 4));
	ATF_CHECK(!pci_nvme_completion_queue_full(2, 0, 4));
	ATF_CHECK(pci_nvme_completion_queue_full(0, 0, 0));
	ATF_CHECK(pci_nvme_completion_queue_full(4, 0, 4));
}

ATF_TC_WITHOUT_HEAD(reset_defers_queue_invalidation);
ATF_TC_BODY(reset_defers_queue_invalidation, tc)
{

	ATF_CHECK(!pci_nvme_reset_must_defer(0, 0));
	ATF_CHECK(pci_nvme_reset_must_defer(1, 0));
	ATF_CHECK(pci_nvme_reset_must_defer(0, 1));
	ATF_CHECK(pci_nvme_reset_must_defer(UINT32_MAX, UINT32_MAX));
}

ATF_TC_WITHOUT_HEAD(snapshot_queue_counts);
ATF_TC_BODY(snapshot_queue_counts, tc)
{

	/* Advertised counts may only narrow, never exceed, the arrays. */
	ATF_CHECK(pci_nvme_snapshot_queue_counts_valid(1, 1, 16));
	ATF_CHECK(pci_nvme_snapshot_queue_counts_valid(16, 16, 16));
	ATF_CHECK(!pci_nvme_snapshot_queue_counts_valid(17, 16, 16));
	ATF_CHECK(!pci_nvme_snapshot_queue_counts_valid(16, 17, 16));
	ATF_CHECK(!pci_nvme_snapshot_queue_counts_valid(0, 16, 16));
	ATF_CHECK(!pci_nvme_snapshot_queue_counts_valid(16, 0, 16));
	ATF_CHECK(!pci_nvme_snapshot_queue_counts_valid(1, 1, 0));
	ATF_CHECK(!pci_nvme_snapshot_queue_counts_valid(UINT32_MAX,
	    UINT32_MAX, 16));
}

ATF_TC_WITHOUT_HEAD(snapshot_queue_shape);
ATF_TC_BODY(snapshot_queue_shape, tc)
{

	/* A created queue: two or more entries, ring indexes in range. */
	ATF_CHECK(pci_nvme_snapshot_queue_shape_valid(true, 2, 0, 1, 2048));
	ATF_CHECK(pci_nvme_snapshot_queue_shape_valid(true, 2048, 2047, 0,
	    2048));
	ATF_CHECK(!pci_nvme_snapshot_queue_shape_valid(true, 2049, 0, 0,
	    2048));
	ATF_CHECK(!pci_nvme_snapshot_queue_shape_valid(true, 1, 0, 0, 2048));
	ATF_CHECK(!pci_nvme_snapshot_queue_shape_valid(true, 0, 0, 0, 2048));
	ATF_CHECK(!pci_nvme_snapshot_queue_shape_valid(true, 4, 4, 0, 2048));
	ATF_CHECK(!pci_nvme_snapshot_queue_shape_valid(true, 4, 0, 4, 2048));

	/* Never-created queues are all zeroes. */
	ATF_CHECK(pci_nvme_snapshot_queue_shape_valid(false, 0, 0, 0, 2048));
	ATF_CHECK(!pci_nvme_snapshot_queue_shape_valid(false, 0, 1, 0, 2048));
	ATF_CHECK(!pci_nvme_snapshot_queue_shape_valid(false, 0, 0, 1, 2048));

	/* Deleted queues may keep stale in-range geometry. */
	ATF_CHECK(pci_nvme_snapshot_queue_shape_valid(false, 4, 3, 2, 2048));
	ATF_CHECK(!pci_nvme_snapshot_queue_shape_valid(false, 4, 4, 0, 2048));
	ATF_CHECK(!pci_nvme_snapshot_queue_shape_valid(false, 4096, 0, 0,
	    2048));
}

ATF_TC_WITHOUT_HEAD(snapshot_pending_cqes);
ATF_TC_BODY(snapshot_pending_cqes, tc)
{

	ATF_CHECK(pci_nvme_snapshot_pending_cqes_valid(true, 0, 65536));
	ATF_CHECK(pci_nvme_snapshot_pending_cqes_valid(true, 65536, 65536));
	ATF_CHECK(!pci_nvme_snapshot_pending_cqes_valid(true, 65537, 65536));
	ATF_CHECK(pci_nvme_snapshot_pending_cqes_valid(false, 0, 65536));
	ATF_CHECK(!pci_nvme_snapshot_pending_cqes_valid(false, 1, 65536));
}

ATF_TC_WITHOUT_HEAD(snapshot_requires_quiesced_device);
ATF_TC_BODY(snapshot_requires_quiesced_device, tc)
{

	ATF_CHECK(pci_nvme_snapshot_quiesced_valid(0, 0, false));
	ATF_CHECK(!pci_nvme_snapshot_quiesced_valid(1, 0, false));
	ATF_CHECK(!pci_nvme_snapshot_quiesced_valid(0, 1, false));
	ATF_CHECK(!pci_nvme_snapshot_quiesced_valid(0, 0, true));
	ATF_CHECK(!pci_nvme_snapshot_quiesced_valid(UINT32_MAX,
	    UINT32_MAX, true));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, doorbell_absolute_index);
	ATF_TP_ADD_TC(tp, doorbell_queue_boundaries);
	ATF_TP_ADD_TC(tp, mmio_access_boundaries);
	ATF_TP_ADD_TC(tp, prp_alignment_and_list_bounds);
	ATF_TP_ADD_TC(tp, ram_command_direction);
	ATF_TP_ADD_TC(tp, dsm_transfer_length);
	ATF_TP_ADD_TC(tp, dsm_skips_leading_empty_range);
	ATF_TP_ADD_TC(tp, completion_phase_is_device_owned);
	ATF_TP_ADD_TC(tp, completion_queue_backpressure);
	ATF_TP_ADD_TC(tp, reset_defers_queue_invalidation);
	ATF_TP_ADD_TC(tp, snapshot_queue_counts);
	ATF_TP_ADD_TC(tp, snapshot_queue_shape);
	ATF_TP_ADD_TC(tp, snapshot_pending_cqes);
	ATF_TP_ADD_TC(tp, snapshot_requires_quiesced_device);
	return (atf_no_error());
}
