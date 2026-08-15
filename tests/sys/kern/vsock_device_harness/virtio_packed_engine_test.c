/*
 * Differential tests for the unadvertised bhyve packed-ring primitives.
 * Expected behavior comes only from the independent VirtIO 1.4 model.
 */
#include <sys/param.h>
#include <sys/types.h>

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <atf-c.h>

#include "virtio_packed.c"
#include "virtio_1_4_spec.h"

#undef VIRTIO_F_RING_PACKED
#define	VIRTIO_F_RING_PACKED		VIRTIO14_F_RING_PACKED
#undef VIRTIO_PACKED_DESC_F_AVAIL
#define	VIRTIO_PACKED_DESC_F_AVAIL	VIRTIO14_PACKED_DESC_F_AVAIL
#undef VIRTIO_PACKED_DESC_F_USED
#define	VIRTIO_PACKED_DESC_F_USED	VIRTIO14_PACKED_DESC_F_USED
#undef VIRTIO_PACKED_EVENT_OFFSET_MASK
#define	VIRTIO_PACKED_EVENT_OFFSET_MASK	VIRTIO14_PACKED_EVENT_OFFSET_MASK
#undef VIRTIO_PACKED_EVENT_WRAP
#define	VIRTIO_PACKED_EVENT_WRAP	VIRTIO14_PACKED_EVENT_WRAP
#undef VIRTIO_PACKED_QUEUE_SIZE_MAX
#define	VIRTIO_PACKED_QUEUE_SIZE_MAX	VIRTIO14_PACKED_QUEUE_SIZE_MAX

static bool
model_available(uint16_t flags, bool wrap)
{
	bool available, used;

	available = (flags & VIRTIO14_PACKED_DESC_F_AVAIL) != 0;
	used = (flags & VIRTIO14_PACKED_DESC_F_USED) != 0;
	return (available == wrap && used != wrap);
}

/*
 * Section 2.8 says a descriptor-specific event fires when that exact
 * descriptor is made available or used.  Deliberately walk the completed
 * descriptors here instead of restating the engine's modular-distance
 * arithmetic: this remains an independent oracle for the boundary case.
 */
static bool
model_event_reached(struct virtio_packed_position event,
    struct virtio_packed_position old, uint16_t queue_size, uint16_t count)
{
	struct virtio_packed_position cursor;

	cursor = old;
	while (count-- != 0) {
		if (cursor.offset == event.offset && cursor.wrap == event.wrap)
			return (true);
		cursor.offset++;
		if (cursor.offset == queue_size) {
			cursor.offset = 0;
			cursor.wrap = !cursor.wrap;
		}
	}
	return (false);
}

ATF_TC_WITHOUT_HEAD(packed_engine_layout);
ATF_TC_BODY(packed_engine_layout, tc)
{

	ATF_CHECK_EQ(sizeof(struct virtio_packed_desc),
	    VIRTIO14_PACKED_DESC_SIZE);
	ATF_CHECK_EQ(offsetof(struct virtio_packed_desc, address),
	    VIRTIO14_PACKED_DESC_ADDR_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_packed_desc, length),
	    VIRTIO14_PACKED_DESC_LEN_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_packed_desc, id),
	    VIRTIO14_PACKED_DESC_ID_OFF);
	ATF_CHECK_EQ(offsetof(struct virtio_packed_desc, flags),
	    VIRTIO14_PACKED_DESC_FLAGS_OFF);
	ATF_CHECK_EQ(sizeof(struct virtio_packed_event),
	    VIRTIO14_PACKED_EVENT_SIZE);
}

ATF_TC_WITHOUT_HEAD(packed_engine_ownership);
ATF_TC_BODY(packed_engine_ownership, tc)
{

	for (unsigned int wrap = 0; wrap <= 1; wrap++) {
		for (uint32_t flags = 0; flags <= UINT16_MAX; flags++) {
			ATF_CHECK_EQ(vi_packed_desc_available(flags, wrap),
			    model_available(flags, wrap));
		}
	}
}

ATF_TC_WITHOUT_HEAD(packed_engine_advance);
ATF_TC_BODY(packed_engine_advance, tc)
{
	static const uint16_t sizes[] = {
		1, 2, 3, 4, 5, 8, 15, 16, 255, 256, 32767, 32768
	};

	for (unsigned int size_index = 0; size_index < nitems(sizes);
	    size_index++) {
		const uint16_t size = sizes[size_index];

		for (unsigned int initial_wrap = 0; initial_wrap <= 1;
		    initial_wrap++) {
			for (uint16_t initial_offset = 0; initial_offset < size;
			    initial_offset++) {
				uint16_t counts[4];

				counts[0] = 0;
				counts[1] = 1;
				counts[2] = size - 1;
				counts[3] = size;

				for (unsigned int count_index = 0;
				    count_index < nitems(counts); count_index++) {
					uint16_t count, offset;
					uint32_t linear;
					bool wrap;

					count = counts[count_index];
					if (count > size)
						continue;
					offset = initial_offset;
					wrap = initial_wrap;
					ATF_REQUIRE_EQ(vi_packed_advance(&offset,
					    &wrap, size, count), 0);
					linear = initial_offset + count;
					ATF_CHECK_EQ(offset, linear % size);
					ATF_CHECK_EQ(wrap,
					    (bool)(initial_wrap ^
					    ((linear / size) & 1)));
				}
			}
		}
	}
}

ATF_TC_WITHOUT_HEAD(packed_engine_rejects_invalid_state);
ATF_TC_BODY(packed_engine_rejects_invalid_state, tc)
{
	uint16_t encoded, offset;
	bool wrap;

	offset = 0;
	wrap = true;
	ATF_CHECK_EQ(vi_packed_advance(&offset, &wrap, 0, 0), EINVAL);
	ATF_CHECK_EQ(vi_packed_advance(&offset, &wrap, 3, 0), 0);
	ATF_CHECK_EQ(vi_packed_advance(&offset, &wrap, 32769, 0), EINVAL);
	ATF_CHECK_EQ(vi_packed_advance(&offset, &wrap, 8, 9), EINVAL);
	ATF_CHECK_EQ(vi_packed_advance(NULL, &wrap, 8, 0), EINVAL);
	ATF_CHECK_EQ(vi_packed_advance(&offset, NULL, 8, 0), EINVAL);
	offset = 8;
	ATF_CHECK_EQ(vi_packed_advance(&offset, &wrap, 8, 0), EINVAL);
	ATF_CHECK_EQ(vi_packed_event_encode(0x7fff, true, 32768,
	    &encoded), 0);
	ATF_CHECK_EQ(encoded, 0xffff);
	ATF_CHECK_EQ(vi_packed_event_encode(8, false, 8, &encoded), EINVAL);
	ATF_CHECK_EQ(vi_packed_event_encode(0, false, 0, &encoded), EINVAL);
	ATF_CHECK_EQ(vi_packed_event_encode(2, false, 3, &encoded), 0);
	ATF_CHECK_EQ(encoded, 2);
	ATF_CHECK_EQ(vi_packed_event_encode(0, false, 32769, &encoded),
	    EINVAL);
	ATF_CHECK_EQ(vi_packed_event_encode(0, false, 8, NULL), EINVAL);
	ATF_CHECK(vi_packed_event_flags_valid(
	    VIRTIO14_PACKED_EVENT_F_ENABLE));
	ATF_CHECK(vi_packed_event_flags_valid(
	    VIRTIO14_PACKED_EVENT_F_DISABLE));
	ATF_CHECK(vi_packed_event_flags_valid(
	    VIRTIO14_PACKED_EVENT_F_DESC));
	ATF_CHECK(!vi_packed_event_flags_valid(
	    VIRTIO14_PACKED_EVENT_F_RESERVED));
	ATF_CHECK(!vi_packed_event_flags_valid(UINT16_MAX));
}

ATF_TC_WITHOUT_HEAD(packed_engine_event_crossing);
ATF_TC_BODY(packed_engine_event_crossing, tc)
{
	static const uint16_t sizes[] = { 1, 2, 3, 5, 8, 255, 32767, 32768 };

	for (unsigned int size_index = 0; size_index < nitems(sizes);
	    size_index++) {
		const uint16_t size = sizes[size_index];
		uint16_t offsets[3];

		offsets[0] = 0;
		offsets[1] = size / 2;
		offsets[2] = size - 1;
		for (unsigned int old_index = 0; old_index < nitems(offsets);
		    old_index++) {
			for (unsigned int old_wrap = 0; old_wrap <= 1;
			    old_wrap++) {
				uint16_t counts[4];

				counts[0] = 0;
				counts[1] = 1;
				counts[2] = size / 2;
				counts[3] = size;
				for (unsigned int count_index = 0;
				    count_index < nitems(counts); count_index++) {
					struct virtio_packed_position event, new, old;
					uint16_t event_offsets[3];
					bool expected, notify;

					old.offset = offsets[old_index];
					old.wrap = old_wrap;
					new = old;
					ATF_REQUIRE_EQ(vi_packed_advance(
					    &new.offset, &new.wrap, size,
					    counts[count_index]), 0);
					event_offsets[0] = old.offset;
					event_offsets[1] = new.offset;
					event_offsets[2] =
					    (old.offset + size - 1) % size;
					for (unsigned int event_index = 0;
					    event_index < nitems(event_offsets);
					    event_index++) {
						for (unsigned int event_wrap = 0;
						    event_wrap <= 1;
						    event_wrap++) {
							event.offset =
							    event_offsets[event_index];
							event.wrap = event_wrap;
							expected = model_event_reached(event, old,
							    size, counts[count_index]);
							ATF_REQUIRE_EQ(
							    vi_packed_need_event(
							    event, old, new, size,
							    &notify), 0);
							ATF_CHECK_EQ(notify,
							    expected);
						}
					}
				}
			}
		}
	}
}

ATF_TC_WITHOUT_HEAD(packed_engine_event_rejects_invalid);
ATF_TC_BODY(packed_engine_event_rejects_invalid, tc)
{
	struct virtio_packed_position event, new, old;
	bool notify;

	event = old = new = (struct virtio_packed_position){ 0, true };
	ATF_CHECK_EQ(vi_packed_need_event(event, old, new, 0, &notify),
	    EINVAL);
	ATF_CHECK_EQ(vi_packed_need_event(event, old, new, 32769, &notify),
	    EINVAL);
	ATF_CHECK_EQ(vi_packed_need_event(event, old, new, 8, NULL), EINVAL);
	event.offset = 8;
	ATF_CHECK_EQ(vi_packed_need_event(event, old, new, 8, &notify),
	    EINVAL);
	event.offset = 0;
	old.offset = 8;
	ATF_CHECK_EQ(vi_packed_need_event(event, old, new, 8, &notify),
	    EINVAL);
	old.offset = 0;
	new.offset = 8;
	ATF_CHECK_EQ(vi_packed_need_event(event, old, new, 8, &notify),
	    EINVAL);
}

ATF_TC_WITHOUT_HEAD(packed_engine_small_event_space_is_exhaustive);
ATF_TC_BODY(packed_engine_small_event_space_is_exhaustive, tc)
{
	/*
	 * Enumerate every legal cursor and threshold for the small queues most
	 * likely to expose wrap and off-by-one mistakes.  The expected result
	 * is calculated directly from the document's 2N cursor space rather
	 * than by calling another production helper.
	 */
	for (uint16_t size = 1; size <= 8; size++) {
		const uint32_t cycle = 2U * size;

		for (unsigned int old_wrap = 0; old_wrap <= 1; old_wrap++) {
			for (uint16_t old_offset = 0; old_offset < size;
			    old_offset++) {
				struct virtio_packed_position old;
				uint32_t old_linear;

				old = (struct virtio_packed_position){
					.offset = old_offset,
					.wrap = old_wrap != 0,
				};
				old_linear = old.offset +
				    (old.wrap ? size : 0);
				for (uint16_t count = 0; count <= size;
				    count++) {
					struct virtio_packed_position new;
					uint32_t new_linear;

					new_linear = (old_linear + count) %
					    cycle;
					new.offset = new_linear % size;
					new.wrap = new_linear >= size;
					for (unsigned int event_wrap = 0;
					    event_wrap <= 1; event_wrap++) {
						for (uint16_t event_offset = 0;
						    event_offset < size;
						    event_offset++) {
							struct
							    virtio_packed_position
							    event;
							bool expected, notify;

							event =
							    (struct
							    virtio_packed_position){
								.offset =
								    event_offset,
								.wrap =
								    event_wrap !=
								    0,
							};
							expected = model_event_reached(event, old,
							    size, count);
							ATF_REQUIRE_EQ(
							    vi_packed_need_event(
							    event, old, new,
							    size, &notify), 0);
							ATF_CHECK_EQ(notify,
							    expected);
						}
					}
				}
			}
		}
	}
}

ATF_TC_WITHOUT_HEAD(packed_engine_checkpoint_cursors);
ATF_TC_BODY(packed_engine_checkpoint_cursors, tc)
{
	bool avail, used, saved;
	uint8_t encoded, expected;

	for (unsigned int a = 0; a <= 1; a++) {
		for (unsigned int u = 0; u <= 1; u++) {
			for (unsigned int s = 0; s <= 1; s++) {
				expected = (a ? 1 : 0) | (u ? 2 : 0) |
				    (s ? 4 : 0);
				encoded = vi_packed_wraps_encode(a, u, s);
				ATF_CHECK_EQ(expected, encoded);
				ATF_REQUIRE_EQ(0, vi_packed_wraps_decode(
				    encoded, &avail, &used, &saved));
				ATF_CHECK_EQ(a != 0, avail);
				ATF_CHECK_EQ(u != 0, used);
				ATF_CHECK_EQ(s != 0, saved);
			}
		}
	}
	ATF_CHECK_EQ(EINVAL, vi_packed_wraps_decode(8, &avail, &used,
	    &saved));
	ATF_CHECK_EQ(EINVAL, vi_packed_wraps_decode(0, NULL, &used,
	    &saved));

	ATF_CHECK_EQ(0, vi_packed_cursors_validate(3, 2, 0, 1));
	ATF_CHECK_EQ(0, vi_packed_cursors_validate(32767, 32766, 0,
	    16384));
	ATF_CHECK_EQ(EINVAL, vi_packed_cursors_validate(0, 0, 0, 0));
	ATF_CHECK_EQ(EINVAL, vi_packed_cursors_validate(3, 3, 0, 0));
	ATF_CHECK_EQ(EINVAL, vi_packed_cursors_validate(3, 0, 3, 0));
	ATF_CHECK_EQ(EINVAL, vi_packed_cursors_validate(3, 0, 0, 3));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, packed_engine_layout);
	ATF_TP_ADD_TC(tp, packed_engine_ownership);
	ATF_TP_ADD_TC(tp, packed_engine_advance);
	ATF_TP_ADD_TC(tp, packed_engine_rejects_invalid_state);
	ATF_TP_ADD_TC(tp, packed_engine_event_crossing);
	ATF_TP_ADD_TC(tp, packed_engine_event_rejects_invalid);
	ATF_TP_ADD_TC(tp, packed_engine_small_event_space_is_exhaustive);
	ATF_TP_ADD_TC(tp, packed_engine_checkpoint_cursors);
	return (atf_no_error());
}
