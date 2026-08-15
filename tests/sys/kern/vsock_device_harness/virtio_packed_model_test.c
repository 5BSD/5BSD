/*
 * Independent VirtIO 1.4 packed-ring model.
 *
 * This test deliberately uses only document-derived values from
 * virtio_1_4_spec.h and byte helpers from virtio_1_4_wire.h.  It is the
 * oracle that the bhyve packed engine will be compared against; it must not
 * include bhyve or FreeBSD VirtIO ring definitions.
 */
#include <sys/param.h>
#include <sys/types.h>

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include "virtio_1_4_spec.h"
#include "virtio_1_4_wire.h"

struct packed_position {
	uint16_t offset;
	bool wrap;
};

static bool
packed_available(uint16_t flags, bool wrap)
{
	bool available, used;

	available = (flags & VIRTIO14_PACKED_DESC_F_AVAIL) != 0;
	used = (flags & VIRTIO14_PACKED_DESC_F_USED) != 0;
	return (available == wrap && used != wrap);
}

static void
packed_advance(struct packed_position *position, uint16_t queue_size,
    uint16_t count)
{

	while (count-- != 0) {
		position->offset++;
		if (position->offset == queue_size) {
			position->offset = 0;
			position->wrap = !position->wrap;
		}
	}
}

static uint16_t
packed_off_wrap(struct packed_position position)
{

	return (position.offset |
	    (position.wrap ? VIRTIO14_PACKED_EVENT_WRAP : 0));
}

/* Section 2.8.9: a descriptor-specific event fires on that descriptor. */
static bool
packed_event_reached(struct packed_position event, struct packed_position old,
    uint16_t queue_size, uint16_t count)
{
	struct packed_position cursor;

	cursor = old;
	while (count-- != 0) {
		if (cursor.offset == event.offset && cursor.wrap == event.wrap)
			return (true);
		packed_advance(&cursor, queue_size, 1);
	}
	return (false);
}

struct model_buffer {
	bool live;
	uint16_t ndescs;
	uint32_t writable_len;
};

struct model_queue_state {
	struct packed_position next_avail;
	struct packed_position next_used;
	bool batch_active;
	bool broken;
	bool interrupts_enabled;
	bool failed_status;
};

static void
model_queue_fail(struct model_queue_state *state)
{

	if (state->broken)
		return;
	state->broken = true;
	state->interrupts_enabled = false;
	state->failed_status = true;
}

static void
model_queue_reset(struct model_queue_state *state)
{

	memset(state, 0, sizeof(*state));
	state->next_avail.wrap = true;
	state->next_used.wrap = true;
}

static bool
model_queue_enable_interrupt(struct model_queue_state *state)
{

	if (state->broken)
		return (false);
	state->interrupts_enabled = true;
	return (true);
}

static bool
model_in_order_batch(const struct model_buffer *buffers, uint16_t queue_size,
    uint16_t first, uint16_t marker, uint16_t available,
    uint16_t *countp)
{
	uint16_t count, cursor;

	if (queue_size == 0 || first >= queue_size || marker >= queue_size ||
	    available == 0 || available > queue_size)
		return (false);
	cursor = first;
	for (count = 1; count <= available; count++) {
		if (!buffers[cursor].live || buffers[cursor].ndescs == 0 ||
		    buffers[cursor].ndescs > queue_size)
			return (false);
		if (cursor == marker) {
			*countp = count;
			return (true);
		}
		cursor = (cursor + buffers[cursor].ndescs) % queue_size;
	}
	return (false);
}

ATF_TC_WITHOUT_HEAD(packed_wire_layout);
ATF_TC_BODY(packed_wire_layout, tc)
{
	uint8_t descriptor[VIRTIO14_PACKED_DESC_SIZE];
	uint8_t event[VIRTIO14_PACKED_EVENT_SIZE];

	memset(descriptor, 0, sizeof(descriptor));
	virtio14_store_le64(descriptor + VIRTIO14_PACKED_DESC_ADDR_OFF,
	    UINT64_C(0x0123456789abcdef));
	virtio14_store_le32(descriptor + VIRTIO14_PACKED_DESC_LEN_OFF,
	    UINT32_C(0xfedcba98));
	virtio14_store_le16(descriptor + VIRTIO14_PACKED_DESC_ID_OFF, 0x7654);
	virtio14_store_le16(descriptor + VIRTIO14_PACKED_DESC_FLAGS_OFF,
	    VIRTIO14_PACKED_DESC_F_NEXT | VIRTIO14_PACKED_DESC_F_WRITE |
	    VIRTIO14_PACKED_DESC_F_AVAIL);
	ATF_CHECK_EQ(virtio14_load_le64(descriptor),
	    UINT64_C(0x0123456789abcdef));
	ATF_CHECK_EQ(virtio14_load_le32(descriptor + 8),
	    UINT32_C(0xfedcba98));
	ATF_CHECK_EQ(virtio14_load_le16(descriptor + 12), 0x7654);
	ATF_CHECK_EQ(virtio14_load_le16(descriptor + 14), 0x0083);

	memset(event, 0, sizeof(event));
	virtio14_store_le16(event + VIRTIO14_PACKED_EVENT_OFF_WRAP_OFF,
	    VIRTIO14_PACKED_EVENT_WRAP | 7);
	virtio14_store_le16(event + VIRTIO14_PACKED_EVENT_FLAGS_OFF,
	    VIRTIO14_PACKED_EVENT_F_DESC);
	ATF_CHECK_EQ(virtio14_load_le16(event), 0x8007);
	ATF_CHECK_EQ(virtio14_load_le16(event + 2), 2);
}

ATF_TC_WITHOUT_HEAD(packed_ownership_truth_table);
ATF_TC_BODY(packed_ownership_truth_table, tc)
{
	static const uint16_t ownership[] = {
		0,
		VIRTIO14_PACKED_DESC_F_AVAIL,
		VIRTIO14_PACKED_DESC_F_USED,
		VIRTIO14_PACKED_DESC_F_AVAIL | VIRTIO14_PACKED_DESC_F_USED,
	};

	for (unsigned int wrap = 0; wrap <= 1; wrap++) {
		for (unsigned int i = 0; i < nitems(ownership); i++) {
			bool expected;

			expected = wrap == 0 ? i == 2 : i == 1;
			ATF_CHECK_EQ(packed_available(ownership[i], wrap),
			    expected);
			ATF_CHECK_EQ(packed_available(ownership[i] |
			    VIRTIO14_PACKED_DESC_F_NEXT |
			    VIRTIO14_PACKED_DESC_F_WRITE, wrap), expected);
		}
	}
}

ATF_TC_WITHOUT_HEAD(packed_wrap_advance);
ATF_TC_BODY(packed_wrap_advance, tc)
{
	/*
	 * Section 2.8.10.1 explicitly permits packed queue sizes that are not
	 * powers of two.  Keep non-power-of-two cases in the independent model
	 * so split-ring assumptions cannot leak into the production engine.
	 */
	static const uint16_t sizes[] = { 1, 2, 3, 4, 5, 8, 15, 16 };

	for (unsigned int size_index = 0; size_index < nitems(sizes);
	    size_index++) {
		const uint16_t size = sizes[size_index];

		for (unsigned int initial_wrap = 0; initial_wrap <= 1;
		    initial_wrap++) {
			for (uint16_t initial_offset = 0; initial_offset < size;
			    initial_offset++) {
				for (uint16_t count = 0; count <= 4 * size;
				    count++) {
					struct packed_position position;
					unsigned int linear, wraps;

					position.offset = initial_offset;
					position.wrap = initial_wrap;
					packed_advance(&position, size, count);
					linear = initial_offset + count;
					wraps = linear / size;
					ATF_CHECK_EQ(position.offset,
					    linear % size);
					ATF_CHECK_EQ(position.wrap,
					    (bool)(initial_wrap ^
					    (wraps & 1)));
					ATF_CHECK_EQ(packed_off_wrap(position) &
					    VIRTIO14_PACKED_EVENT_OFFSET_MASK,
					    position.offset);
					ATF_CHECK_EQ(
					    (packed_off_wrap(position) &
					    VIRTIO14_PACKED_EVENT_WRAP) != 0,
					    position.wrap);
				}
			}
		}
	}
}

ATF_TC_WITHOUT_HEAD(packed_event_values);
ATF_TC_BODY(packed_event_values, tc)
{

	ATF_CHECK(VIRTIO14_PACKED_EVENT_F_ENABLE !=
	    VIRTIO14_PACKED_EVENT_F_DISABLE);
	ATF_CHECK(VIRTIO14_PACKED_EVENT_F_ENABLE !=
	    VIRTIO14_PACKED_EVENT_F_DESC);
	ATF_CHECK(VIRTIO14_PACKED_EVENT_F_DISABLE !=
	    VIRTIO14_PACKED_EVENT_F_DESC);
	ATF_CHECK(VIRTIO14_PACKED_EVENT_F_RESERVED >
	    VIRTIO14_PACKED_EVENT_F_DESC);
	ATF_CHECK_EQ(VIRTIO14_PACKED_QUEUE_SIZE_MAX,
	    VIRTIO14_PACKED_EVENT_OFFSET_MASK + 1);
}

ATF_TC_WITHOUT_HEAD(packed_event_crossing_model);
ATF_TC_BODY(packed_event_crossing_model, tc)
{
	static const uint16_t sizes[] = { 1, 2, 3, 4, 5, 8 };

	for (unsigned int size_index = 0; size_index < nitems(sizes);
	    size_index++) {
		const uint16_t size = sizes[size_index];

		for (unsigned int old_wrap = 0; old_wrap <= 1; old_wrap++) {
			for (uint16_t old_offset = 0; old_offset < size;
			    old_offset++) {
				struct packed_position old, new;

				old.offset = old_offset;
				old.wrap = old_wrap;
				for (uint16_t count = 0; count <= size; count++) {
					new = old;
					packed_advance(&new, size, count);
					/* [old, new): old fires after progress; new does not. */
					ATF_CHECK_EQ(packed_event_reached(old, old, size,
					    count), count != 0);
					ATF_CHECK(!packed_event_reached(new, old, size,
					    count));
				}
			}
		}
	}
}

ATF_TC_WITHOUT_HEAD(packed_in_order_batches);
ATF_TC_BODY(packed_in_order_batches, tc)
{
	struct model_buffer buffers[8];
	uint16_t count;

	memset(buffers, 0, sizeof(buffers));
	/* Three buffers span 2, 1, and 3 descriptors. */
	buffers[0] = (struct model_buffer){ true, 2, 4096 };
	buffers[2] = (struct model_buffer){ true, 1, 0 };
	buffers[3] = (struct model_buffer){ true, 3, 8192 };
	ATF_CHECK(model_in_order_batch(buffers, 8, 0, 3, 3, &count));
	ATF_CHECK_EQ(count, 3);
	/* Skipped buffers are completely used; only the marker length varies. */
	ATF_CHECK_EQ(buffers[0].writable_len, 4096);
	ATF_CHECK_EQ(buffers[2].writable_len, 0);

	/* The same rule crosses the physical end of a non-power-of-two ring. */
	memset(buffers, 0, sizeof(buffers));
	buffers[6] = (struct model_buffer){ true, 1, 64 };
	buffers[0] = (struct model_buffer){ true, 3, 128 };
	buffers[3] = (struct model_buffer){ true, 1, 256 };
	ATF_CHECK(model_in_order_batch(buffers, 7, 6, 3, 3, &count));
	ATF_CHECK_EQ(count, 3);
}

ATF_TC_WITHOUT_HEAD(packed_in_order_rejects_bad_markers);
ATF_TC_BODY(packed_in_order_rejects_bad_markers, tc)
{
	struct model_buffer buffers[5];
	uint16_t count;

	memset(buffers, 0, sizeof(buffers));
	buffers[4] = (struct model_buffer){ true, 2, 8 };
	buffers[1] = (struct model_buffer){ true, 1, 16 };
	ATF_CHECK(!model_in_order_batch(buffers, 5, 4, 5, 2, &count));
	ATF_CHECK(!model_in_order_batch(buffers, 5, 4, 2, 2, &count));
	buffers[1].live = false;
	ATF_CHECK(!model_in_order_batch(buffers, 5, 4, 1, 2, &count));
	buffers[1] = (struct model_buffer){ true, 0, 16 };
	ATF_CHECK(!model_in_order_batch(buffers, 5, 4, 1, 2, &count));
	ATF_CHECK(!model_in_order_batch(buffers, 5, 4, 1, 0, &count));
}

ATF_TC_WITHOUT_HEAD(packed_out_of_order_ids_are_not_positions);
ATF_TC_BODY(packed_out_of_order_ids_are_not_positions, tc)
{
	/*
	 * Completion slots advance in completion order.  The identifier still
	 * names the original owner, so neither a driver nor a test oracle may
	 * equate it with the physical slot receiving the used record.
	 */
	static const uint16_t completion_slot[] = { 0, 1, 3 };
	static const uint16_t owner_id[] = { 3, 0, 1 };
	static const uint16_t owner_span[] = { 2, 1, 1, 1 };
	uint16_t cursor;

	cursor = 0;
	for (unsigned int i = 0; i < nitems(owner_id); i++) {
		ATF_CHECK_EQ(cursor, completion_slot[i]);
		if (i < 2)
			ATF_CHECK(owner_id[i] != completion_slot[i]);
		cursor = (cursor + owner_span[owner_id[i]]) % 4;
	}
	ATF_CHECK_EQ(cursor, 0);
}

ATF_TC_WITHOUT_HEAD(packed_failure_and_reset_lifecycle);
ATF_TC_BODY(packed_failure_and_reset_lifecycle, tc)
{
	struct model_queue_state state;

	model_queue_reset(&state);
	ATF_CHECK_EQ(state.next_avail.offset, 0);
	ATF_CHECK(state.next_avail.wrap);
	ATF_CHECK(state.next_used.wrap);

	state.interrupts_enabled = true;
	state.batch_active = true;
	state.next_avail = (struct packed_position){ 3, false };
	state.next_used = (struct packed_position){ 1, false };
	model_queue_fail(&state);
	ATF_CHECK(state.broken);
	ATF_CHECK(state.failed_status);
	ATF_CHECK(!state.interrupts_enabled);
	ATF_CHECK(!model_queue_enable_interrupt(&state));
	ATF_CHECK(!state.interrupts_enabled);
	/* Repeated observations of the same malformed ring are idempotent. */
	model_queue_fail(&state);
	ATF_CHECK(state.failed_status);

	model_queue_reset(&state);
	ATF_CHECK(!state.broken);
	ATF_CHECK(!state.failed_status);
	ATF_CHECK(!state.batch_active);
	ATF_CHECK(!state.interrupts_enabled);
	ATF_CHECK_EQ(state.next_avail.offset, 0);
	ATF_CHECK(state.next_avail.wrap);
	ATF_CHECK_EQ(state.next_used.offset, 0);
	ATF_CHECK(state.next_used.wrap);
	ATF_CHECK(model_queue_enable_interrupt(&state));
	ATF_CHECK(state.interrupts_enabled);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, packed_wire_layout);
	ATF_TP_ADD_TC(tp, packed_ownership_truth_table);
	ATF_TP_ADD_TC(tp, packed_wrap_advance);
	ATF_TP_ADD_TC(tp, packed_event_values);
	ATF_TP_ADD_TC(tp, packed_event_crossing_model);
	ATF_TP_ADD_TC(tp, packed_in_order_batches);
	ATF_TP_ADD_TC(tp, packed_in_order_rejects_bad_markers);
	ATF_TP_ADD_TC(tp, packed_out_of_order_ids_are_not_positions);
	ATF_TP_ADD_TC(tp, packed_failure_and_reset_lifecycle);
	return (atf_no_error());
}
