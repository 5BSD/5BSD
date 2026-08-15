/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "virtio_scsi_event.h"

int
virtio_scsi_event_state_init(struct virtio_scsi_event_state *state,
    struct virtio_scsi_event_record *records, size_t capacity)
{

	if (state == NULL || records == NULL || capacity == 0 ||
	    capacity > BHYVE_VTSCSI_EVENT_CAPACITY_MAX)
		return (EINVAL);
	memset(state, 0, sizeof(*state));
	memset(records, 0, capacity * sizeof(*records));
	state->records = records;
	state->capacity = capacity;
	return (0);
}

void
virtio_scsi_event_state_reset(struct virtio_scsi_event_state *state,
    bool source_continues)
{

	if (state == NULL || state->records == NULL || state->capacity == 0)
		return;
	memset(state->records, 0,
	    state->capacity * sizeof(*state->records));
	state->head = 0;
	state->count = 0;
	/*
	 * If the source remains subscribed across a guest reset, events could
	 * have occurred while no guest buffer existed.  Force a rescan marker
	 * onto the next real event instead of inventing an event or silently
	 * claiming continuity.
	 */
	state->missed = source_continues;
	if (!source_continues) {
		state->next_source_sequence = 0;
		state->sequence_initialized = false;
	}
}

int
virtio_scsi_event_state_push(struct virtio_scsi_event_state *state,
    const struct virtio_scsi_event_record *record)
{
	struct virtio_scsi_event_record accepted;
	size_t tail;

	if (state == NULL || record == NULL || state->records == NULL ||
	    state->capacity == 0 ||
	    record->source_sequence == 0 ||
	    (record->event & BHYVE_VTSCSI_EVENT_MISSED) != 0)
		return (EINVAL);

	accepted = *record;
	if (state->sequence_initialized &&
	    record->source_sequence != state->next_source_sequence)
		accepted.event |= BHYVE_VTSCSI_EVENT_MISSED;
	state->next_source_sequence = record->source_sequence + 1;
	if (state->next_source_sequence == 0)
		state->next_source_sequence = 1;
	state->sequence_initialized = true;

	if (state->count == state->capacity) {
		/*
		 * Retain already accepted ordering.  A later pop emits the
		 * specification-defined NO_EVENT|EVENTS_MISSED marker after
		 * the retained records, so an older record is never mislabeled
		 * as following this loss.
		 */
		state->missed = true;
		return (ENOSPC);
	}
	if (state->missed) {
		accepted.event |= BHYVE_VTSCSI_EVENT_MISSED;
		state->missed = false;
	}
	tail = (state->head + state->count) % state->capacity;
	state->records[tail] = accepted;
	state->count++;
	return (0);
}

int
virtio_scsi_event_state_skip(struct virtio_scsi_event_state *state,
    uint64_t source_sequence)
{

	if (state == NULL || state->records == NULL || state->capacity == 0 ||
	    source_sequence == 0)
		return (EINVAL);
	if (state->sequence_initialized &&
	    source_sequence != state->next_source_sequence)
		state->missed = true;
	state->next_source_sequence = source_sequence + 1;
	if (state->next_source_sequence == 0)
		state->next_source_sequence = 1;
	state->sequence_initialized = true;
	return (0);
}

bool
virtio_scsi_event_state_pop(struct virtio_scsi_event_state *state,
    struct virtio_scsi_event_record *record)
{

	if (state == NULL || record == NULL || state->records == NULL)
		return (false);
	if (state->count == 0) {
		if (!state->missed)
			return (false);
		memset(record, 0, sizeof(*record));
		record->event = BHYVE_VTSCSI_EVENT_MISSED;
		state->missed = false;
		return (true);
	}
	*record = state->records[state->head];
	memset(&state->records[state->head], 0,
	    sizeof(state->records[state->head]));
	state->head = (state->head + 1) % state->capacity;
	state->count--;
	return (true);
}

bool
virtio_scsi_event_state_pending(const struct virtio_scsi_event_state *state)
{

	return (state != NULL && (state->count != 0 || state->missed));
}

size_t
virtio_scsi_event_state_count(const struct virtio_scsi_event_state *state)
{

	if (state == NULL)
		return (0);
	return (state->count);
}
