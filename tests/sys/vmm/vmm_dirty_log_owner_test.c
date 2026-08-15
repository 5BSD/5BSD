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
#include <dev/vmm/vmm_dirty_log_map.h>
#include <dev/vmm/vmm_dirty_log_owner.h>

#include "../../../sys/dev/vmm/vmm_dirty_log.c"
#include "../../../sys/dev/vmm/vmm_dirty_log_map.c"
#include "../../../sys/dev/vmm/vmm_dirty_log_owner.c"

#define DLPAGE UINT64_C(4096)
#define MAPGEN UINT64_C(23)

static const struct vmm_dirty_log_map_entry entries[] = {
	{ .range = { .gpa = DLPAGE, .length = 4 * DLPAGE },
	  .flags = VMM_DIRTY_LOG_MAP_F_COLLECTABLE },
};
static const struct vmm_dirty_log_range tracked_range = {
	.gpa = DLPAGE,
	.length = 4 * DLPAGE,
};

ATF_TC_WITHOUT_HEAD(observe_and_clear_have_distinct_generation_rules);
ATF_TC_BODY(observe_and_clear_have_distinct_generation_rules, tc)
{
	struct vmm_dirty_log_owner owner = { 0 };
	struct vmm_dirty_log_ticket observe, clear;
	const struct vmm_dirty_log_range request = {
		.gpa = 2 * DLPAGE, .length = DLPAGE,
	};

	(void)tc;
	ATF_REQUIRE_EQ(vmm_dirty_log_owner_enable(&owner, entries,
	    nitems(entries), MAPGEN, &tracked_range), 0);
	ATF_CHECK_EQ(owner.phase, VMM_DIRTY_LOG_OWNER_TRACKING);
	ATF_CHECK_EQ(owner.dirty_generation, 1);
	ATF_REQUIRE_EQ(vmm_dirty_log_owner_begin(&owner, entries,
	    nitems(entries), MAPGEN, &request, VMM_DIRTY_LOG_COLLECT_OBSERVE,
	    &observe), 0);
	ATF_CHECK_EQ(vmm_dirty_log_owner_ticket_check(&owner, &observe), 0);
	ATF_CHECK_EQ(observe.dirty_generation, 1);
	ATF_REQUIRE_EQ(vmm_dirty_log_owner_finish(&owner, &observe), 0);
	ATF_CHECK_EQ(owner.phase, VMM_DIRTY_LOG_OWNER_TRACKING);
	ATF_CHECK_EQ(owner.dirty_generation, 1);
	ATF_REQUIRE_EQ(vmm_dirty_log_owner_begin(&owner, entries,
	    nitems(entries), MAPGEN, &request, VMM_DIRTY_LOG_COLLECT_CLEAR,
	    &clear), 0);
	ATF_CHECK_EQ(vmm_dirty_log_owner_ticket_check(&owner, &clear), 0);
	ATF_CHECK_EQ(clear.dirty_generation, 1);
	ATF_REQUIRE_EQ(vmm_dirty_log_owner_finish(&owner, &clear), 0);
	ATF_CHECK_EQ(owner.phase, VMM_DIRTY_LOG_OWNER_TRACKING);
	ATF_CHECK_EQ(owner.dirty_generation, 2);
}

ATF_TC_WITHOUT_HEAD(rejected_and_aborted_operations_preserve_tracking);
ATF_TC_BODY(rejected_and_aborted_operations_preserve_tracking, tc)
{
	struct vmm_dirty_log_owner owner = { 0 }, before;
	struct vmm_dirty_log_ticket ticket, stale;
	const struct vmm_dirty_log_range request = {
		.gpa = 2 * DLPAGE, .length = DLPAGE,
	};
	const struct vmm_dirty_log_range outside = {
		.gpa = 5 * DLPAGE, .length = DLPAGE,
	};

	(void)tc;
	ATF_REQUIRE_EQ(vmm_dirty_log_owner_enable(&owner, entries,
	    nitems(entries), MAPGEN, &tracked_range), 0);
	before = owner;
	ATF_CHECK_EQ(vmm_dirty_log_owner_begin(&owner, entries, nitems(entries),
	    MAPGEN + 1, &request, VMM_DIRTY_LOG_COLLECT_OBSERVE, &ticket), ESTALE);
	ATF_CHECK_EQ(memcmp(&owner, &before, sizeof(owner)), 0);
	ATF_CHECK_EQ(vmm_dirty_log_owner_begin(&owner, entries, nitems(entries),
	    MAPGEN, &outside, VMM_DIRTY_LOG_COLLECT_OBSERVE, &ticket), EINVAL);
	ATF_CHECK_EQ(memcmp(&owner, &before, sizeof(owner)), 0);
	ATF_CHECK_EQ(vmm_dirty_log_owner_begin(&owner, entries, nitems(entries),
	    MAPGEN, &request, (enum vmm_dirty_log_collect_mode)-1, &ticket),
	    EINVAL);
	ATF_CHECK_EQ(memcmp(&owner, &before, sizeof(owner)), 0);
	ATF_CHECK_EQ(vmm_dirty_log_owner_begin(&owner, entries, nitems(entries),
	    MAPGEN, &request, VMM_DIRTY_LOG_COLLECT_OBSERVE,
	    (struct vmm_dirty_log_ticket *)(void *)&owner), EINVAL);
	ATF_CHECK_EQ(memcmp(&owner, &before, sizeof(owner)), 0);
	ATF_REQUIRE_EQ(vmm_dirty_log_owner_begin(&owner, entries,
	    nitems(entries), MAPGEN, &request, VMM_DIRTY_LOG_COLLECT_CLEAR,
	    &ticket), 0);
	stale = ticket;
	stale.identity++;
	before = owner;
	ATF_CHECK_EQ(vmm_dirty_log_owner_ticket_check(&owner, &stale), ESTALE);
	ATF_CHECK_EQ(memcmp(&owner, &before, sizeof(owner)), 0);
	ATF_CHECK_EQ(vmm_dirty_log_owner_ticket_check(&owner, NULL), EINVAL);
	ATF_CHECK_EQ(memcmp(&owner, &before, sizeof(owner)), 0);
	ATF_CHECK_EQ(vmm_dirty_log_owner_finish(&owner, &stale), ESTALE);
	ATF_CHECK_EQ(memcmp(&owner, &before, sizeof(owner)), 0);
	ATF_CHECK_EQ(vmm_dirty_log_owner_finish(&owner, NULL), EINVAL);
	ATF_CHECK_EQ(vmm_dirty_log_owner_abort(NULL, &ticket), EINVAL);
	ATF_CHECK_EQ(memcmp(&owner, &before, sizeof(owner)), 0);
	ATF_REQUIRE_EQ(vmm_dirty_log_owner_abort(&owner, &ticket), 0);
	ATF_CHECK_EQ(owner.dirty_generation, 1);
	ATF_CHECK_EQ(owner.phase, VMM_DIRTY_LOG_OWNER_TRACKING);
}

ATF_TC_WITHOUT_HEAD(invalidation_revokes_live_ticket_and_generation_exhausts);
ATF_TC_BODY(invalidation_revokes_live_ticket_and_generation_exhausts, tc)
{
	struct vmm_dirty_log_owner owner = { 0 };
	struct vmm_dirty_log_ticket ticket;
	const struct vmm_dirty_log_range request = {
		.gpa = 2 * DLPAGE, .length = DLPAGE,
	};

	(void)tc;
	ATF_REQUIRE_EQ(vmm_dirty_log_owner_enable(&owner, entries,
	    nitems(entries), MAPGEN, &tracked_range), 0);
	ATF_REQUIRE_EQ(vmm_dirty_log_owner_begin(&owner, entries,
	    nitems(entries), MAPGEN, &request, VMM_DIRTY_LOG_COLLECT_CLEAR,
	    &ticket), 0);
	ATF_REQUIRE_EQ(vmm_dirty_log_owner_invalidate(&owner), 0);
	ATF_CHECK_EQ(owner.phase, VMM_DIRTY_LOG_OWNER_OFF);
	ATF_CHECK_EQ(vmm_dirty_log_owner_ticket_check(&owner, &ticket), ESTALE);
	ATF_CHECK_EQ(vmm_dirty_log_owner_finish(&owner, &ticket), ESTALE);
	ATF_REQUIRE_EQ(vmm_dirty_log_owner_enable(&owner, entries,
	    nitems(entries), MAPGEN + 1, &tracked_range), 0);
	ATF_CHECK_EQ(vmm_dirty_log_owner_finish(&owner, &ticket), ESTALE);

	owner = (struct vmm_dirty_log_owner) {
		.identity = UINT64_MAX,
		.phase = VMM_DIRTY_LOG_OWNER_OFF,
	};
	ATF_CHECK_EQ(vmm_dirty_log_owner_enable(&owner, entries, nitems(entries),
	    MAPGEN, &tracked_range), EOVERFLOW);
	ATF_CHECK_EQ(owner.phase, VMM_DIRTY_LOG_OWNER_EXHAUSTED);
	ATF_CHECK_EQ(vmm_dirty_log_owner_invalidate(&owner), EOVERFLOW);

	owner = (struct vmm_dirty_log_owner) {
		.range = tracked_range,
		.map_generation = MAPGEN,
		.dirty_generation = 1,
		.identity = UINT64_MAX,
		.phase = VMM_DIRTY_LOG_OWNER_TRACKING,
	};
	ATF_CHECK_EQ(vmm_dirty_log_owner_begin(&owner, entries, nitems(entries),
	    MAPGEN, &request, VMM_DIRTY_LOG_COLLECT_OBSERVE, &ticket), EOVERFLOW);
	ATF_CHECK_EQ(owner.phase, VMM_DIRTY_LOG_OWNER_EXHAUSTED);
}

ATF_TC_WITHOUT_HEAD(malformed_collecting_owner_is_not_a_live_ticket);
ATF_TC_BODY(malformed_collecting_owner_is_not_a_live_ticket, tc)
{
	struct vmm_dirty_log_owner owner = { 0 }, before;
	struct vmm_dirty_log_ticket ticket;
	const struct vmm_dirty_log_range request = {
		.gpa = 2 * DLPAGE, .length = DLPAGE,
	};

	(void)tc;
	ATF_REQUIRE_EQ(vmm_dirty_log_owner_enable(&owner, entries,
	    nitems(entries), MAPGEN, &tracked_range), 0);
	ATF_REQUIRE_EQ(vmm_dirty_log_owner_begin(&owner, entries,
	    nitems(entries), MAPGEN, &request, VMM_DIRTY_LOG_COLLECT_OBSERVE,
	    &ticket), 0);

	before = owner;
	owner.collection_mode = UINT32_MAX;
	ATF_CHECK_EQ(vmm_dirty_log_owner_ticket_check(&owner, &ticket), EPROTO);
	ATF_CHECK_EQ(vmm_dirty_log_owner_finish(&owner, &ticket), EPROTO);
	ATF_CHECK_EQ(owner.collection_mode, UINT32_MAX);

	owner = before;
	owner.collection_range.length = 0;
	ATF_CHECK_EQ(vmm_dirty_log_owner_ticket_check(&owner, &ticket), EPROTO);
	ATF_CHECK_EQ(vmm_dirty_log_owner_abort(&owner, &ticket), EPROTO);
	ATF_CHECK_EQ(owner.collection_range.length, 0);

	owner = before;
	owner.map_generation = 0;
	ATF_CHECK_EQ(vmm_dirty_log_owner_ticket_check(&owner, &ticket), EPROTO);
	ATF_CHECK_EQ(owner.map_generation, 0);
}

ATF_TC_WITHOUT_HEAD(clear_generation_exhaustion_precedes_backend_access);
ATF_TC_BODY(clear_generation_exhaustion_precedes_backend_access, tc)
{
	struct vmm_dirty_log_owner owner = { 0 };
	struct vmm_dirty_log_ticket ticket;
	const struct vmm_dirty_log_range request = {
		.gpa = 2 * DLPAGE, .length = DLPAGE,
	};

	(void)tc;
	ATF_REQUIRE_EQ(vmm_dirty_log_owner_enable(&owner, entries,
	    nitems(entries), MAPGEN, &tracked_range), 0);
	/* The last generation must be rejected before a backend-clear ticket. */
	owner.dirty_generation = UINT64_MAX;
	memset(&ticket, 0xa5, sizeof(ticket));
	ATF_CHECK_EQ(vmm_dirty_log_owner_begin(&owner, entries,
	    nitems(entries), MAPGEN, &request, VMM_DIRTY_LOG_COLLECT_CLEAR,
	    &ticket), EOVERFLOW);
	ATF_CHECK_EQ(owner.phase, VMM_DIRTY_LOG_OWNER_EXHAUSTED);
	ATF_CHECK_EQ(owner.identity, UINT64_MAX);
	ATF_CHECK_EQ(owner.map_generation, 0);
	ATF_CHECK_EQ(owner.dirty_generation, 0);
	ATF_CHECK_EQ(owner.range.length, 0);
	ATF_CHECK_EQ(owner.collection_range.length, 0);
	ATF_CHECK_EQ(vmm_dirty_log_owner_enable(&owner, entries, nitems(entries),
	    MAPGEN, &tracked_range), EOVERFLOW);
}

ATF_TC_WITHOUT_HEAD(clear_generation_exhaustion_retires_completed_owner);
ATF_TC_BODY(clear_generation_exhaustion_retires_completed_owner, tc)
{
	const struct vmm_dirty_log_range request = {
		.gpa = 2 * DLPAGE, .length = DLPAGE,
	};
	struct vmm_dirty_log_owner owner = {
		.range = tracked_range,
		.collection_range = request,
		.map_generation = MAPGEN,
		.dirty_generation = UINT64_MAX,
		.identity = 42,
		.collection_mode = VMM_DIRTY_LOG_COLLECT_CLEAR,
		.phase = VMM_DIRTY_LOG_OWNER_COLLECTING,
	};
	const struct vmm_dirty_log_ticket ticket = {
		.range = request,
		.map_generation = MAPGEN,
		.dirty_generation = UINT64_MAX,
		.identity = 42,
		.mode = VMM_DIRTY_LOG_COLLECT_CLEAR,
	};

	(void)tc;
	/*
	 * begin() normally prevents this state.  Construct it directly to prove
	 * that corruption discovered after a backend clear retires the owner
	 * instead of wrapping the completed generation back to zero.
	 */
	ATF_CHECK_EQ(vmm_dirty_log_owner_finish(&owner, &ticket), EOVERFLOW);
	ATF_CHECK_EQ(owner.phase, VMM_DIRTY_LOG_OWNER_EXHAUSTED);
	ATF_CHECK_EQ(owner.identity, UINT64_MAX);
	ATF_CHECK_EQ(owner.map_generation, 0);
	ATF_CHECK_EQ(owner.dirty_generation, 0);
	ATF_CHECK_EQ(owner.range.length, 0);
	ATF_CHECK_EQ(owner.collection_range.length, 0);
}

ATF_TC_WITHOUT_HEAD(malformed_noncollecting_owner_cannot_transition);
ATF_TC_BODY(malformed_noncollecting_owner_cannot_transition, tc)
{
	struct vmm_dirty_log_owner owner = { 0 }, before;
	struct vmm_dirty_log_ticket ticket;
	const struct vmm_dirty_log_range request = {
		.gpa = 2 * DLPAGE, .length = DLPAGE,
	};

	(void)tc;
	ATF_REQUIRE_EQ(vmm_dirty_log_owner_enable(&owner, entries,
	    nitems(entries), MAPGEN, &tracked_range), 0);
	owner.collection_mode = VMM_DIRTY_LOG_COLLECT_CLEAR;
	before = owner;
	ATF_CHECK_EQ(vmm_dirty_log_owner_begin(&owner, entries, nitems(entries),
	    MAPGEN, &request, VMM_DIRTY_LOG_COLLECT_OBSERVE, &ticket), EPROTO);
	ATF_CHECK_EQ(memcmp(&owner, &before, sizeof(owner)), 0);

	owner = (struct vmm_dirty_log_owner) {
		.map_generation = MAPGEN,
		.phase = VMM_DIRTY_LOG_OWNER_OFF,
	};
	before = owner;
	ATF_CHECK_EQ(vmm_dirty_log_owner_enable(&owner, entries, nitems(entries),
	    MAPGEN, &tracked_range), EPROTO);
	ATF_CHECK_EQ(vmm_dirty_log_owner_invalidate(&owner), EPROTO);
	ATF_CHECK_EQ(memcmp(&owner, &before, sizeof(owner)), 0);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, observe_and_clear_have_distinct_generation_rules);
	ATF_TP_ADD_TC(tp, rejected_and_aborted_operations_preserve_tracking);
	ATF_TP_ADD_TC(tp, invalidation_revokes_live_ticket_and_generation_exhausts);
	ATF_TP_ADD_TC(tp, malformed_collecting_owner_is_not_a_live_ticket);
	ATF_TP_ADD_TC(tp,
	    clear_generation_exhaustion_precedes_backend_access);
	ATF_TP_ADD_TC(tp,
	    clear_generation_exhaustion_retires_completed_owner);
	ATF_TP_ADD_TC(tp, malformed_noncollecting_owner_cannot_transition);
	return (atf_no_error());
}
