/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <dev/vmm/vmm_address_range.h>

#include "migration_dirty.h"

enum migration_dirty_phase {
	MIGRATION_DIRTY_OFF,
	MIGRATION_DIRTY_TRACKING,
	MIGRATION_DIRTY_COLLECTING,
	MIGRATION_DIRTY_EXHAUSTED,
};

struct migration_dirty_tracker {
	pthread_mutex_t lock;
	struct vmctx *owner;
	uint8_t *active;
	uint8_t *captured;
	size_t bitmap_bytes;
	uint64_t gpa;
	uint64_t length;
	uint64_t identity;
	uint64_t generation;
	uint64_t collection_gpa;
	uint64_t collection_length;
	uint32_t collect_mode;
	uint32_t phase;
	int failure;
};

/* A bhyve process owns one VM.  Keep this ownership explicit and checked. */
static struct migration_dirty_tracker migration_dirty_tracker = {
	.lock = PTHREAD_MUTEX_INITIALIZER,
};

static int
migration_dirty_range_validate(uint64_t gpa, uint64_t length,
    size_t *bitmap_bytes)
{
	uint64_t bytes, pages;

	if (length == 0 ||
	    (gpa & (MIGRATION_DIRTY_GRANULARITY - 1)) != 0 ||
	    (length & (MIGRATION_DIRTY_GRANULARITY - 1)) != 0 ||
	    gpa > UINT64_MAX - (length - 1))
		return (EINVAL);
	pages = length / MIGRATION_DIRTY_GRANULARITY;
	bytes = (pages - 1) / NBBY + 1;
	if (bytes > SIZE_MAX)
		return (EOVERFLOW);
	if (bitmap_bytes != NULL)
		*bitmap_bytes = (size_t)bytes;
	return (0);
}

int
migration_dirty_range_bitmap_bytes(uint64_t gpa, uint64_t length,
    size_t *bitmap_bytes)
{

	if (bitmap_bytes == NULL)
		return (EINVAL);
	return (migration_dirty_range_validate(gpa, length, bitmap_bytes));
}

static void
migration_dirty_exhaust(struct migration_dirty_tracker *tracker)
{

	tracker->phase = MIGRATION_DIRTY_EXHAUSTED;
	tracker->identity = UINT64_MAX;
	tracker->generation = 0;
	tracker->collection_gpa = 0;
	tracker->collection_length = 0;
	tracker->collect_mode = 0;
	tracker->failure = EOVERFLOW;
	if (tracker->active != NULL)
		memset(tracker->active, 0, tracker->bitmap_bytes);
	if (tracker->captured != NULL)
		memset(tracker->captured, 0, tracker->bitmap_bytes);
}

static int
migration_dirty_identity_advance(struct migration_dirty_tracker *tracker)
{

	if (tracker->identity == UINT64_MAX) {
		migration_dirty_exhaust(tracker);
		return (EOVERFLOW);
	}
	tracker->identity++;
	return (0);
}

int
migration_dirty_enable(struct vmctx *ctx, uint64_t gpa, uint64_t length)
{
	struct migration_dirty_tracker *tracker;
	uint8_t *active, *captured;
	size_t bitmap_bytes;
	int error;

	if (ctx == NULL ||
	    (error = migration_dirty_range_validate(gpa, length,
	    &bitmap_bytes)) != 0)
		return (ctx == NULL ? EINVAL : error);
	active = calloc(bitmap_bytes, 1);
	if (active == NULL)
		return (ENOMEM);
	captured = calloc(bitmap_bytes, 1);
	if (captured == NULL) {
		free(active);
		return (ENOMEM);
	}
	tracker = &migration_dirty_tracker;
	pthread_mutex_lock(&tracker->lock);
	if (tracker->phase == MIGRATION_DIRTY_EXHAUSTED)
		error = EOVERFLOW;
	else if (tracker->phase != MIGRATION_DIRTY_OFF)
		error = EBUSY;
	else if ((error = migration_dirty_identity_advance(tracker)) == 0) {
		tracker->owner = ctx;
		tracker->active = active;
		tracker->captured = captured;
		tracker->bitmap_bytes = bitmap_bytes;
		tracker->gpa = gpa;
		tracker->length = length;
		tracker->generation = 1;
		tracker->collection_gpa = 0;
		tracker->collection_length = 0;
		tracker->collect_mode = 0;
		tracker->failure = 0;
		tracker->phase = MIGRATION_DIRTY_TRACKING;
		active = NULL;
		captured = NULL;
	}
	pthread_mutex_unlock(&tracker->lock);
	free(active);
	free(captured);
	return (error);
}

int
migration_dirty_disable(struct vmctx *ctx)
{
	struct migration_dirty_tracker *tracker;
	uint8_t *active, *captured;
	int error;

	if (ctx == NULL)
		return (EINVAL);
	tracker = &migration_dirty_tracker;
	active = captured = NULL;
	pthread_mutex_lock(&tracker->lock);
	if (tracker->phase == MIGRATION_DIRTY_EXHAUSTED)
		error = EOVERFLOW;
	else if (tracker->phase == MIGRATION_DIRTY_OFF || tracker->owner != ctx)
		error = ENOENT;
	else if (tracker->phase == MIGRATION_DIRTY_COLLECTING)
		error = EBUSY;
	else {
		active = tracker->active;
		captured = tracker->captured;
		tracker->owner = NULL;
		tracker->active = NULL;
		tracker->captured = NULL;
		tracker->bitmap_bytes = 0;
		tracker->gpa = 0;
		tracker->length = 0;
		tracker->generation = 0;
		tracker->collection_gpa = 0;
		tracker->collection_length = 0;
		tracker->collect_mode = 0;
		tracker->failure = 0;
		tracker->phase = MIGRATION_DIRTY_OFF;
		error = migration_dirty_identity_advance(tracker);
	}
	pthread_mutex_unlock(&tracker->lock);
	free(active);
	free(captured);
	return (error);
}

int
migration_dirty_bitmap_bytes(struct vmctx *ctx, size_t *bitmap_bytes)
{
	struct migration_dirty_tracker *tracker;
	int error;

	if (ctx == NULL || bitmap_bytes == NULL)
		return (EINVAL);
	tracker = &migration_dirty_tracker;
	pthread_mutex_lock(&tracker->lock);
	if (tracker->phase == MIGRATION_DIRTY_EXHAUSTED)
		error = EOVERFLOW;
	else if (tracker->phase == MIGRATION_DIRTY_OFF || tracker->owner != ctx)
		error = ENOENT;
	else {
		*bitmap_bytes = tracker->bitmap_bytes;
		error = 0;
	}
	pthread_mutex_unlock(&tracker->lock);
	return (error);
}

int
migration_dirty_mark(struct vmctx *ctx, uint64_t gpa, size_t length)
{
	struct migration_dirty_tracker *tracker;
	uint64_t end, first, last, tracked_last;
	int error;

	if (ctx == NULL)
		return (EINVAL);
	if (length == 0)
		return (0);
	if (gpa > UINT64_MAX - (length - 1))
		return (EOVERFLOW);
	end = gpa + length - 1;
	tracker = &migration_dirty_tracker;
	pthread_mutex_lock(&tracker->lock);
	if (tracker->phase == MIGRATION_DIRTY_OFF || tracker->owner != ctx) {
		error = 0;
		goto done;
	}
	if (tracker->phase == MIGRATION_DIRTY_EXHAUSTED) {
		error = EOVERFLOW;
		goto done;
	}
	if (tracker->failure != 0) {
		error = tracker->failure;
		goto done;
	}
	tracked_last = tracker->gpa + tracker->length - 1;
	if (end < tracker->gpa || gpa > tracked_last) {
		error = 0;
		goto done;
	}
	first = MAX(gpa, tracker->gpa) &
	    ~(MIGRATION_DIRTY_GRANULARITY - 1);
	last = MIN(end, tracked_last) &
	    ~(MIGRATION_DIRTY_GRANULARITY - 1);
	for (;;) {
		uint64_t page;

		page = (first - tracker->gpa) / MIGRATION_DIRTY_GRANULARITY;
		tracker->active[page / NBBY] |= UINT8_C(1) << (page % NBBY);
		if (first == last)
			break;
		first += MIGRATION_DIRTY_GRANULARITY;
	}
	error = 0;
done:
	pthread_mutex_unlock(&tracker->lock);
	return (error);
}

void
migration_dirty_fail(struct vmctx *ctx, int error)
{
	struct migration_dirty_tracker *tracker;

	if (ctx == NULL || error == 0)
		return;
	tracker = &migration_dirty_tracker;
	pthread_mutex_lock(&tracker->lock);
	if (tracker->owner == ctx &&
	    tracker->phase != MIGRATION_DIRTY_OFF &&
	    tracker->phase != MIGRATION_DIRTY_EXHAUSTED &&
	    tracker->failure == 0)
		tracker->failure = error;
	pthread_mutex_unlock(&tracker->lock);
}

static int
migration_dirty_ticket_check(const struct migration_dirty_tracker *tracker,
    struct vmctx *ctx, const struct migration_dirty_ticket *ticket)
{

	if (ticket == NULL || tracker->phase != MIGRATION_DIRTY_COLLECTING ||
	    tracker->owner != ctx || ticket->reserved != 0 ||
	    ticket->identity != tracker->identity ||
	    ticket->generation != tracker->generation ||
	    ticket->gpa != tracker->collection_gpa ||
	    ticket->length != tracker->collection_length ||
	    ticket->mode != tracker->collect_mode)
		return (ESTALE);
	return (0);
}

int
migration_dirty_begin_range(struct vmctx *ctx, uint64_t gpa, uint64_t length,
    enum migration_dirty_collect_mode mode, uint8_t *bitmap,
    size_t bitmap_bytes, struct migration_dirty_ticket *ticket)
{
	struct migration_dirty_ticket candidate;
	struct migration_dirty_tracker *tracker;
	uint64_t global_page, local_page, pages, tracked_offset;
	size_t required;
	int error;

	if (ctx == NULL || bitmap == NULL || ticket == NULL ||
	    (mode != MIGRATION_DIRTY_OBSERVE && mode != MIGRATION_DIRTY_CLEAR) ||
	    migration_dirty_range_validate(gpa, length, &required) != 0 ||
	    bitmap_bytes != required ||
	    vmm_address_ranges_overlap(bitmap, bitmap_bytes, ticket,
	    sizeof(*ticket)))
		return (EINVAL);
	tracker = &migration_dirty_tracker;
	pthread_mutex_lock(&tracker->lock);
	if (tracker->phase == MIGRATION_DIRTY_EXHAUSTED)
		error = EOVERFLOW;
	else if (tracker->phase != MIGRATION_DIRTY_TRACKING ||
	    tracker->owner != ctx)
		error = tracker->phase == MIGRATION_DIRTY_OFF ? ENOENT : EBUSY;
	else if (gpa < tracker->gpa || gpa - tracker->gpa >= tracker->length ||
	    length > tracker->length - (gpa - tracker->gpa))
		error = ERANGE;
	else if (tracker->failure != 0)
		error = tracker->failure;
	else if (mode == MIGRATION_DIRTY_CLEAR &&
	    tracker->generation == UINT64_MAX) {
		migration_dirty_exhaust(tracker);
		error = EOVERFLOW;
	} else if ((error = migration_dirty_identity_advance(tracker)) == 0) {
		memset(bitmap, 0, bitmap_bytes);
		tracked_offset = gpa - tracker->gpa;
		global_page = tracked_offset / MIGRATION_DIRTY_GRANULARITY;
		pages = length / MIGRATION_DIRTY_GRANULARITY;
		for (local_page = 0; local_page < pages; local_page++,
		    global_page++) {
			uint8_t mask;

			mask = UINT8_C(1) << (global_page % NBBY);
			if ((tracker->active[global_page / NBBY] & mask) == 0)
				continue;
			bitmap[local_page / NBBY] |=
			    UINT8_C(1) << (local_page % NBBY);
			if (mode == MIGRATION_DIRTY_CLEAR) {
				tracker->captured[global_page / NBBY] |= mask;
				tracker->active[global_page / NBBY] &= ~mask;
			}
		}
		tracker->collection_gpa = gpa;
		tracker->collection_length = length;
		tracker->collect_mode = mode;
		tracker->phase = MIGRATION_DIRTY_COLLECTING;
		candidate = (struct migration_dirty_ticket) {
			.identity = tracker->identity,
			.generation = tracker->generation,
			.gpa = gpa,
			.length = length,
			.mode = mode,
		};
		*ticket = candidate;
	}
	pthread_mutex_unlock(&tracker->lock);
	return (error);
}

int
migration_dirty_begin(struct vmctx *ctx,
    enum migration_dirty_collect_mode mode, uint8_t *bitmap,
    size_t bitmap_bytes, struct migration_dirty_ticket *ticket)
{
	struct migration_dirty_tracker *tracker;
	uint64_t gpa, length;
	int error;

	if (ctx == NULL)
		return (EINVAL);
	tracker = &migration_dirty_tracker;
	pthread_mutex_lock(&tracker->lock);
	if (tracker->phase == MIGRATION_DIRTY_EXHAUSTED)
		error = EOVERFLOW;
	else if (tracker->phase == MIGRATION_DIRTY_OFF || tracker->owner != ctx)
		error = ENOENT;
	else {
		gpa = tracker->gpa;
		length = tracker->length;
		error = 0;
	}
	pthread_mutex_unlock(&tracker->lock);
	if (error != 0)
		return (error);
	return (migration_dirty_begin_range(ctx, gpa, length, mode, bitmap,
	    bitmap_bytes, ticket));
}

static int
migration_dirty_settle(struct vmctx *ctx,
    const struct migration_dirty_ticket *ticket, bool aborting)
{
	struct migration_dirty_tracker *tracker;
	size_t i;
	int error;

	if (ctx == NULL || ticket == NULL)
		return (EINVAL);
	tracker = &migration_dirty_tracker;
	pthread_mutex_lock(&tracker->lock);
	error = migration_dirty_ticket_check(tracker, ctx, ticket);
	if (error != 0)
		goto done;
	/*
	 * A failure reported after begin() invalidates the collection just as an
	 * explicit abort does.  In particular, never publish a successful CLEAR
	 * after a backend has reported that dirty accounting is incomplete.
	 */
	if (tracker->failure != 0) {
		if (ticket->mode == MIGRATION_DIRTY_CLEAR) {
			for (i = 0; i < tracker->bitmap_bytes; i++)
				tracker->active[i] |= tracker->captured[i];
			memset(tracker->captured, 0, tracker->bitmap_bytes);
		}
		tracker->collection_gpa = 0;
		tracker->collection_length = 0;
		tracker->collect_mode = 0;
		tracker->phase = MIGRATION_DIRTY_TRACKING;
		error = tracker->failure;
		goto done;
	}
	if (ticket->mode == MIGRATION_DIRTY_CLEAR) {
		if (aborting) {
			for (i = 0; i < tracker->bitmap_bytes; i++)
				tracker->active[i] |= tracker->captured[i];
		} else
			tracker->generation++;
		memset(tracker->captured, 0, tracker->bitmap_bytes);
	}
	tracker->collection_gpa = 0;
	tracker->collection_length = 0;
	tracker->collect_mode = 0;
	tracker->phase = MIGRATION_DIRTY_TRACKING;
done:
	pthread_mutex_unlock(&tracker->lock);
	return (error);
}

int
migration_dirty_finish(struct vmctx *ctx,
    const struct migration_dirty_ticket *ticket)
{

	return (migration_dirty_settle(ctx, ticket, false));
}

int
migration_dirty_abort(struct vmctx *ctx,
    const struct migration_dirty_ticket *ticket)
{

	return (migration_dirty_settle(ctx, ticket, true));
}
