/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/types.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include <dev/vmm/vmm_dirty_log.h>
#include <dev/vmm/vmm_dirty_log_collector.h>
#include <dev/vmm/vmm_dirty_log_map.h>
#include <dev/vmm/vmm_dirty_log_owner.h>

#include "../../../sys/dev/vmm/vmm_dirty_log.c"
#include "../../../sys/dev/vmm/vmm_dirty_log_map.c"
#include "../../../sys/dev/vmm/vmm_dirty_log_owner.c"
#include "../../../sys/dev/vmm/vmm_dirty_log_collector.c"

#define DLPAGE UINT64_C(4096)

struct fake_collector {
	struct vmm_dirty_log_leaf leaves[3];
	uint32_t count;
	uint32_t queries;
	uint32_t clears;
	uint32_t fail_after;
	uint32_t clear_fail_after;
};

struct invalidating_collector {
	struct vmm_dirty_log_owner *owner;
	uint32_t queries;
};

static int
fake_query(void *arg, uint64_t gpa, struct vmm_dirty_log_leaf *leaf)
{
	struct fake_collector *fake;

	fake = arg;
	if (fake == NULL || leaf == NULL)
		return (EINVAL);
	fake->queries++;
	if (fake->fail_after != 0 && fake->queries >= fake->fail_after)
		return (EIO);
	for (uint32_t i = 0; i < fake->count; i++) {
		uint64_t last;

		last = fake->leaves[i].range.gpa + fake->leaves[i].range.length - 1;
		if (fake->leaves[i].range.gpa <= gpa && gpa <= last) {
			*leaf = fake->leaves[i];
			return (0);
		}
	}
	return (ENOENT);
}

static int
fake_clear(void *arg, uint64_t gpa, struct vmm_dirty_log_leaf *leaf)
{
	struct fake_collector *fake;
	uint32_t saved_queries;
	int error;

	fake = arg;
	if (fake == NULL)
		return (EINVAL);
	fake->clears++;
	if (fake->clear_fail_after != 0 &&
	    fake->clears >= fake->clear_fail_after)
		return (EIO);
	/* Reuse lookup without counting a clear as an observation query. */
	saved_queries = fake->queries;
	error = fake_query(arg, gpa, leaf);
	fake->queries = saved_queries;
	return (error);
}

/*
 * Deliberately violate the collector callback contract with a well-formed,
 * aligned leaf that starts after the requested address.  This is distinct
 * from a malformed range: a backend must also prove that its result covers
 * the query point before any observed state is published.
 */
static int
noncovering_query(void *arg __unused, uint64_t gpa,
    struct vmm_dirty_log_leaf *leaf)
{

	if (leaf == NULL || gpa > UINT64_MAX - 2 * DLPAGE)
		return (EINVAL);
	*leaf = (struct vmm_dirty_log_leaf) {
		.range = { .gpa = gpa + DLPAGE, .length = DLPAGE },
		.dirty = true,
	};
	return (0);
}

/*
 * Model a future backend callback which reaches a reset/detach edge after it
 * has supplied a valid leaf.  The common collector must not publish its
 * staging bitmap after that ticket has been revoked.
 */
static int
invalidate_owner_query(void *arg, uint64_t gpa,
    struct vmm_dirty_log_leaf *leaf)
{
	struct invalidating_collector *invalidating;
	int error;

	invalidating = arg;
	if (invalidating == NULL || invalidating->owner == NULL || leaf == NULL)
		return (EINVAL);
	if (gpa != DLPAGE || invalidating->queries != 0)
		return (EPROTO);
	invalidating->queries++;
	*leaf = (struct vmm_dirty_log_leaf) {
		.range = { .gpa = DLPAGE, .length = 4 * DLPAGE },
		.dirty = true,
	};
	error = vmm_dirty_log_owner_invalidate(invalidating->owner);
	return (error);
}

static const struct vmm_dirty_log_map_entry entries[] = {
	{ .range = { .gpa = DLPAGE, .length = 4 * DLPAGE },
	  .flags = VMM_DIRTY_LOG_MAP_F_COLLECTABLE },
};
static const struct vmm_dirty_log_range tracked = {
	.gpa = DLPAGE, .length = 4 * DLPAGE,
};
static const struct vmm_dirty_log_collector collector = {
	.query = fake_query,
	.clear = fake_clear,
};

ATF_TC_WITHOUT_HEAD(observe_publishes_only_after_full_scan);
ATF_TC_BODY(observe_publishes_only_after_full_scan, tc)
{
	struct vmm_dirty_log_owner owner = { 0 };
	struct vmm_dirty_log_ticket ticket;
	struct fake_collector fake = {
		.leaves = {
			{ .range = { .gpa = DLPAGE, .length = 2 * DLPAGE },
			  .dirty = false },
			{ .range = { .gpa = 3 * DLPAGE, .length = 2 * DLPAGE },
			  .dirty = true },
		},
		.count = 2,
	};
	uint8_t staging[1], bitmap[1] = { 0xa5 };
	bool dirty;

	(void)tc;
	ATF_REQUIRE_EQ(vmm_dirty_log_owner_enable(&owner, entries,
	    nitems(entries), 1, &tracked), 0);
	ATF_REQUIRE_EQ(vmm_dirty_log_owner_begin(&owner, entries,
	    nitems(entries), 1, &tracked, VMM_DIRTY_LOG_COLLECT_OBSERVE,
	    &ticket), 0);
	ATF_REQUIRE_EQ(vmm_dirty_log_collect(&owner, &ticket, &collector, &fake,
	    staging, sizeof(staging), bitmap, sizeof(bitmap)), 0);
	ATF_REQUIRE_EQ(vmm_dirty_log_bitmap_isset(&tracked, bitmap,
	    sizeof(bitmap), DLPAGE, &dirty), 0);
	ATF_CHECK(!dirty);
	ATF_REQUIRE_EQ(vmm_dirty_log_bitmap_isset(&tracked, bitmap,
	    sizeof(bitmap), 3 * DLPAGE, &dirty), 0);
	ATF_CHECK(dirty);
	ATF_CHECK_EQ(fake.queries, 2);
	ATF_CHECK_EQ(vmm_dirty_log_owner_finish(&owner, &ticket), 0);
}

ATF_TC_WITHOUT_HEAD(failed_scan_and_stale_ticket_do_not_publish);
ATF_TC_BODY(failed_scan_and_stale_ticket_do_not_publish, tc)
{
	struct vmm_dirty_log_owner owner = { 0 };
	struct vmm_dirty_log_ticket ticket;
	struct fake_collector fake = {
		.leaves = {
			{ .range = { .gpa = DLPAGE, .length = 2 * DLPAGE },
			  .dirty = true },
			{ .range = { .gpa = 3 * DLPAGE, .length = 2 * DLPAGE },
			  .dirty = true },
		},
		.count = 2,
		.fail_after = 2,
	};
	uint8_t staging[1], bitmap[1] = { 0x5a }, before[1];

	(void)tc;
	ATF_REQUIRE_EQ(vmm_dirty_log_owner_enable(&owner, entries,
	    nitems(entries), 1, &tracked), 0);
	ATF_REQUIRE_EQ(vmm_dirty_log_owner_begin(&owner, entries,
	    nitems(entries), 1, &tracked, VMM_DIRTY_LOG_COLLECT_CLEAR,
	    &ticket), 0);
	memcpy(before, bitmap, sizeof(bitmap));
	ATF_CHECK_EQ(vmm_dirty_log_collect(&owner, &ticket, &collector, &fake,
	    staging, sizeof(staging), bitmap, sizeof(bitmap)), EIO);
	ATF_CHECK_EQ(memcmp(bitmap, before, sizeof(bitmap)), 0);
	ATF_CHECK_EQ(vmm_dirty_log_owner_invalidate(&owner), 0);
	fake.queries = 0;
	ATF_CHECK_EQ(vmm_dirty_log_collect(&owner, &ticket, &collector, &fake,
	    staging, sizeof(staging), bitmap, sizeof(bitmap)), ESTALE);
	ATF_CHECK_EQ(fake.queries, 0);
	ATF_CHECK_EQ(memcmp(bitmap, before, sizeof(bitmap)), 0);
}

ATF_TC_WITHOUT_HEAD(superleaf_is_clipped_to_ticket_range);
ATF_TC_BODY(superleaf_is_clipped_to_ticket_range, tc)
{
	struct vmm_dirty_log_owner owner = { 0 };
	struct vmm_dirty_log_ticket ticket;
	struct fake_collector fake = {
		.leaves = {
			{ .range = { .gpa = 0, .length = 6 * DLPAGE },
			  .dirty = true },
		},
		.count = 1,
	};
	uint8_t staging[1], bitmap[1] = { 0 };

	(void)tc;
	ATF_REQUIRE_EQ(vmm_dirty_log_owner_enable(&owner, entries,
	    nitems(entries), 1, &tracked), 0);
	ATF_REQUIRE_EQ(vmm_dirty_log_owner_begin(&owner, entries,
	    nitems(entries), 1, &tracked, VMM_DIRTY_LOG_COLLECT_OBSERVE,
	    &ticket), 0);
	ATF_REQUIRE_EQ(vmm_dirty_log_collect(&owner, &ticket, &collector, &fake,
	    staging, sizeof(staging), bitmap, sizeof(bitmap)), 0);
	ATF_CHECK_EQ(bitmap[0], 0x0f);
	ATF_CHECK_EQ(fake.queries, 1);
	ATF_CHECK_EQ(vmm_dirty_log_owner_finish(&owner, &ticket), 0);
}

ATF_TC_WITHOUT_HEAD(malformed_leaf_and_alias_do_not_publish);
ATF_TC_BODY(malformed_leaf_and_alias_do_not_publish, tc)
{
	struct vmm_dirty_log_owner owner = { 0 };
	struct vmm_dirty_log_ticket ticket;
	struct fake_collector fake = {
		.leaves = {
			{ .range = { .gpa = DLPAGE, .length = DLPAGE + 1 },
			  .dirty = true },
		},
		.count = 1,
	};
	uint8_t staging[1], bitmap[1] = { 0x3c }, before[1];

	(void)tc;
	ATF_REQUIRE_EQ(vmm_dirty_log_owner_enable(&owner, entries,
	    nitems(entries), 1, &tracked), 0);
	ATF_REQUIRE_EQ(vmm_dirty_log_owner_begin(&owner, entries,
	    nitems(entries), 1, &tracked, VMM_DIRTY_LOG_COLLECT_OBSERVE,
	    &ticket), 0);
	memcpy(before, bitmap, sizeof(bitmap));
	ATF_CHECK_EQ(vmm_dirty_log_collect(&owner, &ticket, &collector, &fake,
	    staging, sizeof(staging), bitmap, sizeof(bitmap)), EPROTO);
	ATF_CHECK_EQ(memcmp(bitmap, before, sizeof(bitmap)), 0);
	fake.queries = 0;
	ATF_CHECK_EQ(vmm_dirty_log_collect(&owner, &ticket, &collector, &fake,
	    bitmap, sizeof(bitmap), bitmap, sizeof(bitmap)), EINVAL);
	ATF_CHECK_EQ(fake.queries, 0);
	ATF_CHECK_EQ(memcmp(bitmap, before, sizeof(bitmap)), 0);
}

ATF_TC_WITHOUT_HEAD(noncovering_leaf_does_not_publish);
ATF_TC_BODY(noncovering_leaf_does_not_publish, tc)
{
	struct vmm_dirty_log_owner owner = { 0 };
	struct vmm_dirty_log_ticket ticket;
	struct vmm_dirty_log_collector bad_collector = {
		.query = noncovering_query,
	};
	uint8_t staging[1], bitmap[1] = { 0xc3 }, before[1];

	(void)tc;
	ATF_REQUIRE_EQ(vmm_dirty_log_owner_enable(&owner, entries,
	    nitems(entries), 1, &tracked), 0);
	ATF_REQUIRE_EQ(vmm_dirty_log_owner_begin(&owner, entries,
	    nitems(entries), 1, &tracked, VMM_DIRTY_LOG_COLLECT_OBSERVE,
	    &ticket), 0);
	memcpy(before, bitmap, sizeof(bitmap));
	ATF_CHECK_EQ(vmm_dirty_log_collect(&owner, &ticket, &bad_collector,
	    NULL, staging, sizeof(staging), bitmap, sizeof(bitmap)), EPROTO);
	ATF_CHECK_EQ(memcmp(bitmap, before, sizeof(bitmap)), 0);
}

ATF_TC_WITHOUT_HEAD(revoked_during_callback_does_not_publish);
ATF_TC_BODY(revoked_during_callback_does_not_publish, tc)
{
	struct vmm_dirty_log_owner owner = { 0 };
	struct vmm_dirty_log_ticket ticket;
	struct invalidating_collector invalidating = { .owner = &owner };
	struct vmm_dirty_log_collector callback = {
		.query = invalidate_owner_query,
	};
	uint8_t staging[1], bitmap[1] = { 0x96 }, before[1];

	(void)tc;
	ATF_REQUIRE_EQ(vmm_dirty_log_owner_enable(&owner, entries,
	    nitems(entries), 1, &tracked), 0);
	ATF_REQUIRE_EQ(vmm_dirty_log_owner_begin(&owner, entries,
	    nitems(entries), 1, &tracked, VMM_DIRTY_LOG_COLLECT_OBSERVE,
	    &ticket), 0);
	memcpy(before, bitmap, sizeof(bitmap));
	ATF_CHECK_EQ(vmm_dirty_log_collect(&owner, &ticket, &callback,
	    &invalidating, staging, sizeof(staging), bitmap, sizeof(bitmap)),
	    ESTALE);
	ATF_CHECK_EQ(invalidating.queries, 1);
	ATF_CHECK_EQ(owner.phase, VMM_DIRTY_LOG_OWNER_OFF);
	ATF_CHECK_EQ(memcmp(bitmap, before, sizeof(bitmap)), 0);
}

ATF_TC_WITHOUT_HEAD(clear_preflights_complete_range);
ATF_TC_BODY(clear_preflights_complete_range, tc)
{
	struct vmm_dirty_log_owner owner = { 0 };
	struct vmm_dirty_log_ticket ticket;
	struct fake_collector fake = {
		.leaves = {
			{ .range = { .gpa = DLPAGE, .length = 2 * DLPAGE },
			  .dirty = true },
			{ .range = { .gpa = 3 * DLPAGE, .length = 2 * DLPAGE },
			  .dirty = false },
		},
		.count = 2,
	};

	(void)tc;
	ATF_REQUIRE_EQ(vmm_dirty_log_owner_enable(&owner, entries,
	    nitems(entries), 1, &tracked), 0);
	ATF_REQUIRE_EQ(vmm_dirty_log_owner_begin(&owner, entries,
	    nitems(entries), 1, &tracked, VMM_DIRTY_LOG_COLLECT_CLEAR,
	    &ticket), 0);
	ATF_REQUIRE_EQ(vmm_dirty_log_clear(&owner, &ticket, &collector, &fake),
	    0);
	ATF_CHECK_EQ(fake.queries, 2);
	ATF_CHECK_EQ(fake.clears, 2);
	ATF_REQUIRE_EQ(vmm_dirty_log_owner_finish(&owner, &ticket), 0);
	ATF_CHECK_EQ(owner.dirty_generation, 2);
}

ATF_TC_WITHOUT_HEAD(clear_failure_during_preflight_changes_nothing);
ATF_TC_BODY(clear_failure_during_preflight_changes_nothing, tc)
{
	struct vmm_dirty_log_owner owner = { 0 };
	struct vmm_dirty_log_ticket ticket;
	struct fake_collector fake = {
		.leaves = {
			{ .range = { .gpa = DLPAGE, .length = 2 * DLPAGE },
			  .dirty = true },
			{ .range = { .gpa = 3 * DLPAGE, .length = 2 * DLPAGE },
			  .dirty = true },
		},
		.count = 2,
		.fail_after = 2,
	};

	(void)tc;
	ATF_REQUIRE_EQ(vmm_dirty_log_owner_enable(&owner, entries,
	    nitems(entries), 1, &tracked), 0);
	ATF_REQUIRE_EQ(vmm_dirty_log_owner_begin(&owner, entries,
	    nitems(entries), 1, &tracked, VMM_DIRTY_LOG_COLLECT_CLEAR,
	    &ticket), 0);
	ATF_CHECK_EQ(vmm_dirty_log_clear(&owner, &ticket, &collector, &fake),
	    EIO);
	ATF_CHECK_EQ(fake.queries, 2);
	ATF_CHECK_EQ(fake.clears, 0);
	ATF_REQUIRE_EQ(vmm_dirty_log_owner_abort(&owner, &ticket), 0);
}

ATF_TC_WITHOUT_HEAD(clear_callback_failure_requires_invalidation);
ATF_TC_BODY(clear_callback_failure_requires_invalidation, tc)
{
	struct vmm_dirty_log_owner owner = { 0 };
	struct vmm_dirty_log_ticket ticket;
	struct fake_collector fake = {
		.leaves = {
			{ .range = { .gpa = DLPAGE, .length = 2 * DLPAGE },
			  .dirty = true },
			{ .range = { .gpa = 3 * DLPAGE, .length = 2 * DLPAGE },
			  .dirty = true },
		},
		.count = 2,
		.clear_fail_after = 2,
	};

	(void)tc;
	ATF_REQUIRE_EQ(vmm_dirty_log_owner_enable(&owner, entries,
	    nitems(entries), 1, &tracked), 0);
	ATF_REQUIRE_EQ(vmm_dirty_log_owner_begin(&owner, entries,
	    nitems(entries), 1, &tracked, VMM_DIRTY_LOG_COLLECT_CLEAR,
	    &ticket), 0);
	ATF_CHECK_EQ(vmm_dirty_log_clear(&owner, &ticket, &collector, &fake),
	    EIO);
	ATF_CHECK_EQ(fake.queries, 2);
	ATF_CHECK_EQ(fake.clears, 2);
	/* The common layer cannot roll a partially changed backend back. */
	ATF_CHECK_EQ(owner.phase, VMM_DIRTY_LOG_OWNER_COLLECTING);
	ATF_REQUIRE_EQ(vmm_dirty_log_owner_invalidate(&owner), 0);
	ATF_CHECK_EQ(owner.phase, VMM_DIRTY_LOG_OWNER_OFF);
	ATF_CHECK_EQ(vmm_dirty_log_owner_finish(&owner, &ticket), ESTALE);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, observe_publishes_only_after_full_scan);
	ATF_TP_ADD_TC(tp, failed_scan_and_stale_ticket_do_not_publish);
	ATF_TP_ADD_TC(tp, superleaf_is_clipped_to_ticket_range);
	ATF_TP_ADD_TC(tp, malformed_leaf_and_alias_do_not_publish);
	ATF_TP_ADD_TC(tp, noncovering_leaf_does_not_publish);
	ATF_TP_ADD_TC(tp, revoked_during_callback_does_not_publish);
	ATF_TP_ADD_TC(tp, clear_preflights_complete_range);
	ATF_TP_ADD_TC(tp, clear_failure_during_preflight_changes_nothing);
	ATF_TP_ADD_TC(tp, clear_callback_failure_requires_invalidation);
	return (atf_no_error());
}
