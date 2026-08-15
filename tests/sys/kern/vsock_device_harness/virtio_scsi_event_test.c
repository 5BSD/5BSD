/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <atf-c.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "virtio_scsi_event.c"

/* Independent values transcribed from VirtIO 1.4 section 5.6.6.4. */
#define	SPEC_EVENT_MISSED	UINT32_C(0x80000000)
#define	SPEC_TRANSPORT_RESET	UINT32_C(1)
#define	SPEC_PARAM_CHANGE	UINT32_C(3)

static struct virtio_scsi_event_record
event(uint64_t sequence, uint32_t type, uint32_t reason, uint8_t lun)
{
	struct virtio_scsi_event_record record;

	memset(&record, 0, sizeof(record));
	record.source_sequence = sequence;
	record.event = type;
	record.reason = reason;
	record.lun[3] = lun;
	return (record);
}

ATF_TC_WITHOUT_HEAD(ordered_wrap_and_capacity);
ATF_TC_BODY(ordered_wrap_and_capacity, tc)
{
	struct virtio_scsi_event_record records[2], input, output;
	struct virtio_scsi_event_state state;

	ATF_REQUIRE_EQ(virtio_scsi_event_state_init(&state, records, 2), 0);
	input = event(10, SPEC_TRANSPORT_RESET, 1, 4);
	ATF_REQUIRE_EQ(virtio_scsi_event_state_push(&state, &input), 0);
	input = event(11, SPEC_PARAM_CHANGE, 2, 5);
	ATF_REQUIRE_EQ(virtio_scsi_event_state_push(&state, &input), 0);
	ATF_CHECK(virtio_scsi_event_state_pending(&state));
	ATF_CHECK_EQ(virtio_scsi_event_state_count(&state), 2);
	ATF_REQUIRE(virtio_scsi_event_state_pop(&state, &output));
	ATF_CHECK_EQ(output.source_sequence, 10);
	ATF_CHECK_EQ(output.lun[3], 4);
	input = event(12, SPEC_TRANSPORT_RESET, 3, 6);
	ATF_REQUIRE_EQ(virtio_scsi_event_state_push(&state, &input), 0);
	ATF_REQUIRE(virtio_scsi_event_state_pop(&state, &output));
	ATF_CHECK_EQ(output.source_sequence, 11);
	ATF_REQUIRE(virtio_scsi_event_state_pop(&state, &output));
	ATF_CHECK_EQ(output.source_sequence, 12);
	ATF_CHECK(!virtio_scsi_event_state_pop(&state, &output));
	ATF_CHECK(!virtio_scsi_event_state_pending(&state));
}

ATF_TC_WITHOUT_HEAD(sequence_gap_marks_next_delivery);
ATF_TC_BODY(sequence_gap_marks_next_delivery, tc)
{
	struct virtio_scsi_event_record records[3], input, output;
	struct virtio_scsi_event_state state;

	ATF_REQUIRE_EQ(virtio_scsi_event_state_init(&state, records, 3), 0);
	input = event(20, SPEC_TRANSPORT_RESET, 1, 1);
	ATF_REQUIRE_EQ(virtio_scsi_event_state_push(&state, &input), 0);
	input = event(22, SPEC_PARAM_CHANGE, 2, 2);
	ATF_REQUIRE_EQ(virtio_scsi_event_state_push(&state, &input), 0);
	ATF_REQUIRE(virtio_scsi_event_state_pop(&state, &output));
	ATF_CHECK_EQ(output.event, SPEC_TRANSPORT_RESET);
	ATF_REQUIRE(virtio_scsi_event_state_pop(&state, &output));
	ATF_CHECK_EQ(output.event, SPEC_PARAM_CHANGE | SPEC_EVENT_MISSED);
}

ATF_TC_WITHOUT_HEAD(sequence_wrap_skips_reserved_zero);
ATF_TC_BODY(sequence_wrap_skips_reserved_zero, tc)
{
	struct virtio_scsi_event_record records[2], input, output;
	struct virtio_scsi_event_state state;

	ATF_REQUIRE_EQ(virtio_scsi_event_state_init(&state, records, 2), 0);
	input = event(UINT64_MAX, SPEC_TRANSPORT_RESET, 1, 1);
	ATF_REQUIRE_EQ(virtio_scsi_event_state_push(&state, &input), 0);
	input = event(1, SPEC_PARAM_CHANGE, 2, 2);
	ATF_REQUIRE_EQ(virtio_scsi_event_state_push(&state, &input), 0);
	ATF_REQUIRE(virtio_scsi_event_state_pop(&state, &output));
	ATF_CHECK_EQ(output.event, SPEC_TRANSPORT_RESET);
	ATF_REQUIRE(virtio_scsi_event_state_pop(&state, &output));
	ATF_CHECK_EQ(output.event, SPEC_PARAM_CHANGE);
}

ATF_TC_WITHOUT_HEAD(saturation_preserves_order_and_reports_loss);
ATF_TC_BODY(saturation_preserves_order_and_reports_loss, tc)
{
	struct virtio_scsi_event_record records[2], input, output;
	struct virtio_scsi_event_state state;

	ATF_REQUIRE_EQ(virtio_scsi_event_state_init(&state, records, 2), 0);
	input = event(30, SPEC_TRANSPORT_RESET, 1, 1);
	ATF_REQUIRE_EQ(virtio_scsi_event_state_push(&state, &input), 0);
	input = event(31, SPEC_PARAM_CHANGE, 2, 2);
	ATF_REQUIRE_EQ(virtio_scsi_event_state_push(&state, &input), 0);
	input = event(32, SPEC_TRANSPORT_RESET, 3, 3);
	ATF_CHECK_EQ(virtio_scsi_event_state_push(&state, &input), ENOSPC);
	ATF_REQUIRE(virtio_scsi_event_state_pop(&state, &output));
	ATF_CHECK_EQ(output.source_sequence, 30);
	ATF_CHECK_EQ(output.event, SPEC_TRANSPORT_RESET);
	ATF_REQUIRE(virtio_scsi_event_state_pop(&state, &output));
	ATF_CHECK_EQ(output.source_sequence, 31);
	ATF_CHECK_EQ(output.event, SPEC_PARAM_CHANGE);
	ATF_REQUIRE(virtio_scsi_event_state_pop(&state, &output));
	ATF_CHECK_EQ(output.event, SPEC_EVENT_MISSED);
	ATF_CHECK_EQ(output.reason, 0);
	ATF_CHECK(!virtio_scsi_event_state_pop(&state, &output));
}

ATF_TC_WITHOUT_HEAD(filtered_events_preserve_source_continuity);
ATF_TC_BODY(filtered_events_preserve_source_continuity, tc)
{
	struct virtio_scsi_event_record records[2], input, output;
	struct virtio_scsi_event_state state;

	ATF_REQUIRE_EQ(virtio_scsi_event_state_init(&state, records, 2), 0);
	input = event(50, SPEC_TRANSPORT_RESET, 1, 1);
	ATF_REQUIRE_EQ(virtio_scsi_event_state_push(&state, &input), 0);
	ATF_REQUIRE_EQ(virtio_scsi_event_state_skip(&state, 51), 0);
	input = event(52, SPEC_TRANSPORT_RESET, 1, 2);
	ATF_REQUIRE_EQ(virtio_scsi_event_state_push(&state, &input), 0);
	ATF_REQUIRE(virtio_scsi_event_state_pop(&state, &output));
	ATF_CHECK_EQ(output.event, SPEC_TRANSPORT_RESET);
	ATF_REQUIRE(virtio_scsi_event_state_pop(&state, &output));
	ATF_CHECK_EQ(output.event, SPEC_TRANSPORT_RESET);
}

ATF_TC_WITHOUT_HEAD(loss_marks_first_later_accepted_event);
ATF_TC_BODY(loss_marks_first_later_accepted_event, tc)
{
	struct virtio_scsi_event_record records[1], input, output;
	struct virtio_scsi_event_state state;

	ATF_REQUIRE_EQ(virtio_scsi_event_state_init(&state, records, 1), 0);
	input = event(60, SPEC_TRANSPORT_RESET, 1, 1);
	ATF_REQUIRE_EQ(virtio_scsi_event_state_push(&state, &input), 0);
	input = event(61, SPEC_TRANSPORT_RESET, 1, 2);
	ATF_REQUIRE_EQ(virtio_scsi_event_state_push(&state, &input), ENOSPC);
	ATF_REQUIRE(virtio_scsi_event_state_pop(&state, &output));
	ATF_CHECK_EQ(output.source_sequence, 60);
	input = event(62, SPEC_PARAM_CHANGE, 2, 3);
	ATF_REQUIRE_EQ(virtio_scsi_event_state_push(&state, &input), 0);
	ATF_REQUIRE(virtio_scsi_event_state_pop(&state, &output));
	ATF_CHECK_EQ(output.source_sequence, 62);
	ATF_CHECK_EQ(output.event, SPEC_PARAM_CHANGE | SPEC_EVENT_MISSED);
	ATF_CHECK(!virtio_scsi_event_state_pop(&state, &output));
}

ATF_TC_WITHOUT_HEAD(reset_continuity_is_explicit);
ATF_TC_BODY(reset_continuity_is_explicit, tc)
{
	struct virtio_scsi_event_record records[2], input, output;
	struct virtio_scsi_event_state state;

	ATF_REQUIRE_EQ(virtio_scsi_event_state_init(&state, records, 2), 0);
	input = event(40, SPEC_TRANSPORT_RESET, 1, 1);
	ATF_REQUIRE_EQ(virtio_scsi_event_state_push(&state, &input), 0);
	virtio_scsi_event_state_reset(&state, true);
	ATF_CHECK_EQ(virtio_scsi_event_state_count(&state), 0);
	ATF_REQUIRE(virtio_scsi_event_state_pop(&state, &output));
	ATF_CHECK_EQ(output.event, SPEC_EVENT_MISSED);
	input = event(41, SPEC_PARAM_CHANGE, 2, 2);
	ATF_REQUIRE_EQ(virtio_scsi_event_state_push(&state, &input), 0);
	ATF_REQUIRE(virtio_scsi_event_state_pop(&state, &output));
	ATF_CHECK_EQ(output.event, SPEC_PARAM_CHANGE);

	virtio_scsi_event_state_reset(&state, false);
	input = event(3, SPEC_TRANSPORT_RESET, 3, 3);
	ATF_REQUIRE_EQ(virtio_scsi_event_state_push(&state, &input), 0);
	ATF_REQUIRE(virtio_scsi_event_state_pop(&state, &output));
	ATF_CHECK_EQ(output.event, SPEC_TRANSPORT_RESET);
}

ATF_TC_WITHOUT_HEAD(invalid_contract);
ATF_TC_BODY(invalid_contract, tc)
{
	struct virtio_scsi_event_record record, records[1];
	struct virtio_scsi_event_state state;

	ATF_CHECK_EQ(virtio_scsi_event_state_init(NULL, records, 1), EINVAL);
	ATF_CHECK_EQ(virtio_scsi_event_state_init(&state, NULL, 1), EINVAL);
	ATF_CHECK_EQ(virtio_scsi_event_state_init(&state, records, 0), EINVAL);
	ATF_CHECK_EQ(virtio_scsi_event_state_init(&state, records,
	    BHYVE_VTSCSI_EVENT_CAPACITY_MAX + 1), EINVAL);
	ATF_REQUIRE_EQ(virtio_scsi_event_state_init(&state, records, 1), 0);
	record = event(1, SPEC_TRANSPORT_RESET | SPEC_EVENT_MISSED, 0, 0);
	ATF_CHECK_EQ(virtio_scsi_event_state_push(&state, &record), EINVAL);
	record = event(0, SPEC_TRANSPORT_RESET, 0, 0);
	ATF_CHECK_EQ(virtio_scsi_event_state_push(&state, &record), EINVAL);
	ATF_CHECK_EQ(virtio_scsi_event_state_skip(&state, 0), EINVAL);
	ATF_CHECK(!virtio_scsi_event_state_pop(NULL, &record));
	ATF_CHECK(!virtio_scsi_event_state_pop(&state, NULL));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, ordered_wrap_and_capacity);
	ATF_TP_ADD_TC(tp, sequence_gap_marks_next_delivery);
	ATF_TP_ADD_TC(tp, sequence_wrap_skips_reserved_zero);
	ATF_TP_ADD_TC(tp, saturation_preserves_order_and_reports_loss);
	ATF_TP_ADD_TC(tp, filtered_events_preserve_source_continuity);
	ATF_TP_ADD_TC(tp, loss_marks_first_later_accepted_event);
	ATF_TP_ADD_TC(tp, reset_continuity_is_explicit);
	ATF_TP_ADD_TC(tp, invalid_contract);
	return (atf_no_error());
}
