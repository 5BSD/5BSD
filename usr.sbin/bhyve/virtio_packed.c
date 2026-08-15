/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>

#include "virtio_packed.h"

bool
vi_packed_desc_available(uint16_t flags, bool wrap)
{
	bool available, used;

	available = (flags & VIRTIO_PACKED_DESC_F_AVAIL) != 0;
	used = (flags & VIRTIO_PACKED_DESC_F_USED) != 0;
	return (available == wrap && used != wrap);
}

bool
vi_packed_event_flags_valid(uint16_t flags)
{

	return (flags == VIRTIO_PACKED_EVENT_F_ENABLE ||
	    flags == VIRTIO_PACKED_EVENT_F_DISABLE ||
	    flags == VIRTIO_PACKED_EVENT_F_DESC);
}

int
vi_packed_advance(uint16_t *offset, bool *wrap, uint16_t queue_size,
    uint16_t count)
{
	uint32_t linear, wraps;

	if (offset == NULL || wrap == NULL || queue_size == 0 ||
	    queue_size > VIRTIO_PACKED_QUEUE_SIZE_MAX ||
	    *offset >= queue_size ||
	    count > queue_size)
		return (EINVAL);
	linear = (uint32_t)*offset + count;
	wraps = linear / queue_size;
	*offset = linear % queue_size;
	if ((wraps & 1) != 0)
		*wrap = !*wrap;
	return (0);
}

int
vi_packed_event_encode(uint16_t offset, bool wrap, uint16_t queue_size,
    uint16_t *off_wrap)
{

	if (off_wrap == NULL || queue_size == 0 ||
	    queue_size > VIRTIO_PACKED_QUEUE_SIZE_MAX ||
	    offset >= queue_size)
		return (EINVAL);
	*off_wrap = offset | (wrap ? VIRTIO_PACKED_EVENT_WRAP : 0);
	return (0);
}

int
vi_packed_need_event(struct virtio_packed_position event,
    struct virtio_packed_position old, struct virtio_packed_position new,
    uint16_t queue_size, bool *notify)
{
	uint32_t cycle, event_linear, event_distance, new_linear, old_linear;
	uint32_t used_distance;

	if (notify == NULL || queue_size == 0 ||
	    queue_size > VIRTIO_PACKED_QUEUE_SIZE_MAX ||
	    event.offset >= queue_size || old.offset >= queue_size ||
	    new.offset >= queue_size)
		return (EINVAL);
	cycle = 2U * queue_size;
	event_linear = event.offset + (event.wrap ? queue_size : 0);
	old_linear = old.offset + (old.wrap ? queue_size : 0);
	new_linear = new.offset + (new.wrap ? queue_size : 0);
	event_distance = (event_linear + cycle - old_linear) % cycle;
	used_distance = (new_linear + cycle - old_linear) % cycle;
	/*
	 * old identifies the first descriptor in the completed interval and
	 * new identifies the descriptor immediately following it.  Event
	 * suppression requests a notification if event lies in [old, new).
	 * A caller never completes more than one queue revolution at a time,
	 * so identical full positions mean no progress rather than 2N entries.
	 */
	*notify = used_distance != 0 && event_distance < used_distance;
	return (0);
}

uint8_t
vi_packed_wraps_encode(bool avail, bool used, bool saved)
{

	return ((avail ? VIRTIO_PACKED_WRAP_AVAIL : 0) |
	    (used ? VIRTIO_PACKED_WRAP_USED : 0) |
	    (saved ? VIRTIO_PACKED_WRAP_SAVED : 0));
}

int
vi_packed_wraps_decode(uint8_t encoded, bool *avail, bool *used, bool *saved)
{

	if (avail == NULL || used == NULL || saved == NULL ||
	    (encoded & ~VIRTIO_PACKED_WRAP_VALID) != 0)
		return (EINVAL);
	*avail = (encoded & VIRTIO_PACKED_WRAP_AVAIL) != 0;
	*used = (encoded & VIRTIO_PACKED_WRAP_USED) != 0;
	*saved = (encoded & VIRTIO_PACKED_WRAP_SAVED) != 0;
	return (0);
}

int
vi_packed_cursors_validate(uint16_t queue_size, uint16_t next_avail,
    uint16_t next_used, uint16_t saved_used)
{

	if (queue_size == 0 || queue_size > VIRTIO_PACKED_QUEUE_SIZE_MAX ||
	    next_avail >= queue_size || next_used >= queue_size ||
	    saved_used >= queue_size)
		return (EINVAL);
	return (0);
}
