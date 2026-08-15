/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <atf-c.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

#include "../../../../usr.sbin/bhyve/migration_dirty.c"

static struct vmctx *const owner = (struct vmctx *)(uintptr_t)0x1000;
static struct vmctx *const foreign = (struct vmctx *)(uintptr_t)0x2000;

ATF_TC_WITHOUT_HEAD(mark_observe_and_clip);
ATF_TC_BODY(mark_observe_and_clip, tc)
{
	struct migration_dirty_ticket ticket;
	uint8_t bitmap[2];

	ATF_REQUIRE_EQ(migration_dirty_enable(owner, 0x1000, 16 * 4096), 0);
	ATF_REQUIRE_EQ(migration_dirty_mark(owner, 0x1001, 1), 0);
	ATF_REQUIRE_EQ(migration_dirty_mark(owner, 0x3fff, 2), 0);
	ATF_REQUIRE_EQ(migration_dirty_mark(owner, 0, 0x1001), 0);
	ATF_REQUIRE_EQ(migration_dirty_mark(owner, 0x11000, 4096), 0);
	memset(bitmap, 0xa5, sizeof(bitmap));
	memset(&ticket, 0xa5, sizeof(ticket));
	ATF_REQUIRE_EQ(migration_dirty_begin(owner, MIGRATION_DIRTY_OBSERVE,
	    bitmap, sizeof(bitmap), &ticket), 0);
	ATF_CHECK_EQ(bitmap[0], 0x0d);
	ATF_CHECK_EQ(bitmap[1], 0x00);
	ATF_CHECK_EQ(ticket.mode, MIGRATION_DIRTY_OBSERVE);
	ATF_REQUIRE_EQ(migration_dirty_finish(owner, &ticket), 0);
	ATF_REQUIRE_EQ(migration_dirty_disable(owner), 0);
}

ATF_TC_WITHOUT_HEAD(clear_cut_preserves_later_writes);
ATF_TC_BODY(clear_cut_preserves_later_writes, tc)
{
	struct migration_dirty_ticket first, second;
	uint8_t bitmap;

	ATF_REQUIRE_EQ(migration_dirty_enable(owner, 0, 8 * 4096), 0);
	ATF_REQUIRE_EQ(migration_dirty_mark(owner, 0, 1), 0);
	ATF_REQUIRE_EQ(migration_dirty_begin(owner, MIGRATION_DIRTY_CLEAR,
	    &bitmap, sizeof(bitmap), &first), 0);
	ATF_CHECK_EQ(bitmap, 0x01);
	ATF_CHECK_EQ(first.generation, 1);
	ATF_REQUIRE_EQ(migration_dirty_mark(owner, 4096, 1), 0);
	ATF_CHECK_EQ(migration_dirty_begin(owner, MIGRATION_DIRTY_OBSERVE,
	    &bitmap, sizeof(bitmap), &second), EBUSY);
	ATF_REQUIRE_EQ(migration_dirty_finish(owner, &first), 0);
	ATF_REQUIRE_EQ(migration_dirty_begin(owner, MIGRATION_DIRTY_CLEAR,
	    &bitmap, sizeof(bitmap), &second), 0);
	ATF_CHECK_EQ(bitmap, 0x02);
	ATF_CHECK_EQ(second.generation, 2);
	ATF_REQUIRE_EQ(migration_dirty_finish(owner, &second), 0);
	ATF_REQUIRE_EQ(migration_dirty_disable(owner), 0);
}

ATF_TC_WITHOUT_HEAD(clear_abort_merges_generations);
ATF_TC_BODY(clear_abort_merges_generations, tc)
{
	struct migration_dirty_ticket clear, observe;
	uint8_t bitmap;

	ATF_REQUIRE_EQ(migration_dirty_enable(owner, 0, 8 * 4096), 0);
	ATF_REQUIRE_EQ(migration_dirty_mark(owner, 0, 1), 0);
	ATF_REQUIRE_EQ(migration_dirty_begin(owner, MIGRATION_DIRTY_CLEAR,
	    &bitmap, sizeof(bitmap), &clear), 0);
	ATF_CHECK_EQ(bitmap, 0x01);
	ATF_CHECK_EQ(clear.generation, 1);
	ATF_REQUIRE_EQ(migration_dirty_mark(owner, 2 * 4096, 1), 0);
	ATF_REQUIRE_EQ(migration_dirty_abort(owner, &clear), 0);
	ATF_REQUIRE_EQ(migration_dirty_begin(owner, MIGRATION_DIRTY_OBSERVE,
	    &bitmap, sizeof(bitmap), &observe), 0);
	ATF_CHECK_EQ(bitmap, 0x05);
	ATF_CHECK_EQ(observe.generation, clear.generation);
	ATF_REQUIRE_EQ(migration_dirty_finish(owner, &observe), 0);
	ATF_REQUIRE_EQ(migration_dirty_disable(owner), 0);
}

ATF_TC_WITHOUT_HEAD(failure_and_alias_are_atomic);
ATF_TC_BODY(failure_and_alias_are_atomic, tc)
{
	struct migration_dirty_ticket ticket, before;
	union {
		struct migration_dirty_ticket ticket;
		uint8_t bytes[sizeof(struct migration_dirty_ticket)];
	} alias;
	uint8_t bitmap;

	ATF_CHECK_EQ(migration_dirty_enable(NULL, 0, 4096), EINVAL);
	ATF_CHECK_EQ(migration_dirty_enable(owner, 1, 4096), EINVAL);
	ATF_CHECK_EQ(migration_dirty_enable(owner, 0, 4095), EINVAL);
	ATF_REQUIRE_EQ(migration_dirty_enable(owner, 0, 8 * 4096), 0);
	ATF_CHECK_EQ(migration_dirty_enable(foreign, 0, 8 * 4096), EBUSY);
	memset(&alias, 0x5a, sizeof(alias));
	before = alias.ticket;
	ATF_CHECK_EQ(migration_dirty_begin(owner, MIGRATION_DIRTY_OBSERVE,
	    alias.bytes, 1, &alias.ticket), EINVAL);
	ATF_CHECK(memcmp(&alias.ticket, &before, sizeof(before)) == 0);
	memset(&ticket, 0x5a, sizeof(ticket));
	before = ticket;
	migration_dirty_fail(owner, EIO);
	ATF_CHECK_EQ(migration_dirty_begin(owner, MIGRATION_DIRTY_OBSERVE,
	    &bitmap, sizeof(bitmap), &ticket), EIO);
	ATF_CHECK(memcmp(&ticket, &before, sizeof(before)) == 0);
	ATF_REQUIRE_EQ(migration_dirty_disable(owner), 0);
}

ATF_TC_WITHOUT_HEAD(failure_during_clear_aborts_cut);
ATF_TC_BODY(failure_during_clear_aborts_cut, tc)
{
	struct migration_dirty_ticket ticket;
	uint8_t bitmap;

	(void)tc;
	ATF_REQUIRE_EQ(migration_dirty_enable(owner, 0, 8 * 4096), 0);
	ATF_REQUIRE_EQ(migration_dirty_mark(owner, 0, 1), 0);
	ATF_REQUIRE_EQ(migration_dirty_begin(owner, MIGRATION_DIRTY_CLEAR,
	    &bitmap, sizeof(bitmap), &ticket), 0);
	ATF_CHECK_EQ(bitmap, 0x01);
	ATF_REQUIRE_EQ(migration_dirty_mark(owner, 4096, 1), 0);
	migration_dirty_fail(owner, EIO);
	ATF_CHECK_EQ(migration_dirty_finish(owner, &ticket), EIO);
	ATF_CHECK_EQ(migration_dirty_tracker.phase, MIGRATION_DIRTY_TRACKING);
	ATF_CHECK_EQ(migration_dirty_tracker.generation, ticket.generation);
	ATF_CHECK_EQ(migration_dirty_tracker.active[0], 0x03);
	ATF_CHECK_EQ(migration_dirty_tracker.captured[0], 0x00);
	ATF_REQUIRE_EQ(migration_dirty_disable(owner), 0);
}

struct mark_thread_arg {
	atomic_bool stop;
};

static void *
mark_thread(void *arg)
{
	struct mark_thread_arg *state;
	uint64_t page;

	state = arg;
	page = 0;
	while (!atomic_load_explicit(&state->stop, memory_order_relaxed)) {
		(void)migration_dirty_mark(owner, page * 4096, 1);
		page = (page + 1) % 8;
	}
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(concurrent_mark_and_clear);
ATF_TC_BODY(concurrent_mark_and_clear, tc)
{
	struct mark_thread_arg state;
	struct migration_dirty_ticket ticket;
	pthread_t thread;
	uint8_t bitmap;
	unsigned int i;

	ATF_REQUIRE_EQ(migration_dirty_enable(owner, 0, 8 * 4096), 0);
	atomic_init(&state.stop, false);
	ATF_REQUIRE_EQ(pthread_create(&thread, NULL, mark_thread, &state), 0);
	for (i = 0; i < 1000; i++) {
		ATF_REQUIRE_EQ(migration_dirty_begin(owner, MIGRATION_DIRTY_CLEAR,
		    &bitmap, sizeof(bitmap), &ticket), 0);
		ATF_REQUIRE_EQ(migration_dirty_finish(owner, &ticket), 0);
	}
	atomic_store_explicit(&state.stop, true, memory_order_relaxed);
	ATF_REQUIRE_EQ(pthread_join(thread, NULL), 0);
	ATF_REQUIRE_EQ(migration_dirty_begin(owner, MIGRATION_DIRTY_OBSERVE,
	    &bitmap, sizeof(bitmap), &ticket), 0);
	ATF_REQUIRE_EQ(migration_dirty_finish(owner, &ticket), 0);
	ATF_REQUIRE_EQ(migration_dirty_disable(owner), 0);
}

ATF_TC_WITHOUT_HEAD(range_clear_uses_local_bitmap_indices);
ATF_TC_BODY(range_clear_uses_local_bitmap_indices, tc)
{
	struct migration_dirty_ticket range_ticket, full_ticket;
	uint8_t full[2], range;

	(void)tc;
	ATF_REQUIRE_EQ(migration_dirty_enable(owner, 0, 16 * 4096), 0);
	ATF_REQUIRE_EQ(migration_dirty_mark(owner, 0 * 4096, 1), 0);
	ATF_REQUIRE_EQ(migration_dirty_mark(owner, 7 * 4096, 1), 0);
	ATF_REQUIRE_EQ(migration_dirty_mark(owner, 8 * 4096, 1), 0);
	ATF_REQUIRE_EQ(migration_dirty_mark(owner, 15 * 4096, 1), 0);
	ATF_REQUIRE_EQ(migration_dirty_begin_range(owner, 3 * 4096, 8 * 4096,
	    MIGRATION_DIRTY_CLEAR, &range, sizeof(range), &range_ticket), 0);
	ATF_CHECK_EQ(range, 0x30);
	ATF_CHECK_EQ(range_ticket.gpa, 3 * 4096);
	ATF_CHECK_EQ(range_ticket.length, 8 * 4096);
	ATF_REQUIRE_EQ(migration_dirty_finish(owner, &range_ticket), 0);
	ATF_REQUIRE_EQ(migration_dirty_begin(owner, MIGRATION_DIRTY_OBSERVE,
	    full, sizeof(full), &full_ticket), 0);
	ATF_CHECK_EQ(full[0], 0x01);
	ATF_CHECK_EQ(full[1], 0x80);
	ATF_REQUIRE_EQ(migration_dirty_finish(owner, &full_ticket), 0);
	ATF_REQUIRE_EQ(migration_dirty_disable(owner), 0);
}

ATF_TC_WITHOUT_HEAD(range_abort_merges_only_captured_bits);
ATF_TC_BODY(range_abort_merges_only_captured_bits, tc)
{
	struct migration_dirty_ticket range_ticket, full_ticket;
	uint8_t full[2], range;

	(void)tc;
	ATF_REQUIRE_EQ(migration_dirty_enable(owner, 0, 16 * 4096), 0);
	ATF_REQUIRE_EQ(migration_dirty_mark(owner, 5 * 4096, 1), 0);
	ATF_REQUIRE_EQ(migration_dirty_begin_range(owner, 4 * 4096, 8 * 4096,
	    MIGRATION_DIRTY_CLEAR, &range, sizeof(range), &range_ticket), 0);
	ATF_CHECK_EQ(range, 0x02);
	ATF_REQUIRE_EQ(migration_dirty_mark(owner, 6 * 4096, 1), 0);
	ATF_REQUIRE_EQ(migration_dirty_abort(owner, &range_ticket), 0);
	ATF_REQUIRE_EQ(migration_dirty_begin(owner, MIGRATION_DIRTY_OBSERVE,
	    full, sizeof(full), &full_ticket), 0);
	ATF_CHECK_EQ(full[0], 0x60);
	ATF_CHECK_EQ(full[1], 0x00);
	ATF_REQUIRE_EQ(migration_dirty_finish(owner, &full_ticket), 0);
	ATF_REQUIRE_EQ(migration_dirty_disable(owner), 0);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, mark_observe_and_clip);
	ATF_TP_ADD_TC(tp, clear_cut_preserves_later_writes);
	ATF_TP_ADD_TC(tp, clear_abort_merges_generations);
	ATF_TP_ADD_TC(tp, failure_and_alias_are_atomic);
	ATF_TP_ADD_TC(tp, failure_during_clear_aborts_cut);
	ATF_TP_ADD_TC(tp, concurrent_mark_and_clear);
	ATF_TP_ADD_TC(tp, range_clear_uses_local_bitmap_indices);
	ATF_TP_ADD_TC(tp, range_abort_merges_only_captured_bits);
	return (atf_no_error());
}
