/*
 * Independent tests for the architecture-neutral balloon PFN parser.
 * Wire bytes and expected addresses are transcribed from VirtIO 1.4 section
 * 5.5 rather than obtained from production structures.
 */
#include <sys/param.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include "virtio_balloon_host.c"

struct callback_state {
	uint64_t addresses[8];
	size_t count;
	uint64_t reject;
};

struct range_state {
	uint64_t addresses[4];
	size_t lengths[4];
	size_t count;
	size_t fail_at;
};

static int
record_pfn(void *arg, uint64_t gpa)
{
	struct callback_state *state;

	state = arg;
	ATF_REQUIRE(state->count < nitems(state->addresses));
	state->addresses[state->count++] = gpa;
	return (gpa == state->reject ? EFAULT : 0);
}

static int
count_pfn(void *arg, uint64_t gpa __unused)
{
	size_t *count;

	count = arg;
	(*count)++;
	return (0);
}

static int
record_range(void *arg, uint64_t gpa, size_t length)
{
	struct range_state *state;

	state = arg;
	ATF_REQUIRE(state->count < nitems(state->addresses));
	state->addresses[state->count] = gpa;
	state->lengths[state->count] = length;
	state->count++;
	return (state->fail_at != 0 && state->count == state->fail_at ?
	    EIO : 0);
}

ATF_TC_WITHOUT_HEAD(fragmented_memory_statistics);
ATF_TC_BODY(fragmented_memory_statistics, tc)
{
	static const uint8_t bytes[] = {
		/* MEMTOT (5), 0x0102030405060708. */
		0x05, 0x00, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
		/* Unknown tag 0x1234: ignored. */
		0x34, 0x12, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
		/* MEMFREE (4), 4096. */
		0x04, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		/* MEMTOT again: arbitrary order and latest sample wins. */
		0x05, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};
	struct virtio_balloon_stats stats;
	struct iovec iov[] = {
		{ __DECONST(void *, bytes), 1 },
		{ __DECONST(void *, bytes + 1), 12 },
		{ __DECONST(void *, bytes + 13), 7 },
		{ __DECONST(void *, bytes + 20), sizeof(bytes) - 20 },
	};

	memset(&stats, 0xa5, sizeof(stats));
	ATF_REQUIRE_EQ(virtio_balloon_parse_stats(iov, nitems(iov), &stats), 0);
	ATF_CHECK_EQ(stats.vbs_entries, 4);
	ATF_CHECK_EQ(stats.vbs_ignored, 1);
	ATF_CHECK_EQ(stats.vbs_present, (1U << 4) | (1U << 5));
	ATF_CHECK_EQ(stats.vbs_value[4], UINT64_C(4096));
	ATF_CHECK_EQ(stats.vbs_value[5], UINT64_C(42));
	ATF_CHECK_EQ(stats.vbs_value[0], 0);
}

ATF_TC_WITHOUT_HEAD(statistics_tag_boundary);
ATF_TC_BODY(statistics_tag_boundary, tc)
{
	/*
	 * Section 5.5.6 defines a fixed set of statistic tags.  The parser
	 * records tags strictly below BHYVE_BALLOON_STAT_COUNT and ignores the
	 * rest; the boundary is load-bearing because vbs_value has exactly
	 * BHYVE_BALLOON_STAT_COUNT entries, so accepting the first out-of-range
	 * tag would overrun the array.  Exercise the last valid tag and the
	 * first ignored tag explicitly.
	 */
	static const uint8_t bytes[] = {
		/* tag 0 (minimum), 0x11. */
		0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		/* tag COUNT-1 == 9 (maximum recorded), 0x99. */
		0x09, 0x00, 0x99, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		/* tag COUNT == 10 (first ignored), value must not be stored. */
		0x0a, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	};
	struct virtio_balloon_stats stats;
	struct iovec iov;

	ATF_REQUIRE_EQ(BHYVE_BALLOON_STAT_COUNT, 10U);
	memset(&stats, 0xa5, sizeof(stats));
	iov.iov_base = __DECONST(void *, bytes);
	iov.iov_len = sizeof(bytes);
	ATF_REQUIRE_EQ(virtio_balloon_parse_stats(&iov, 1, &stats), 0);
	ATF_CHECK_EQ(stats.vbs_entries, 3);
	ATF_CHECK_EQ(stats.vbs_ignored, 1);
	ATF_CHECK_EQ(stats.vbs_present,
	    (uint16_t)((1U << 0) | (1U << (BHYVE_BALLOON_STAT_COUNT - 1))));
	ATF_CHECK_EQ(stats.vbs_value[0], UINT64_C(0x11));
	ATF_CHECK_EQ(stats.vbs_value[BHYVE_BALLOON_STAT_COUNT - 1],
	    UINT64_C(0x99));
	/* The ignored tag left no present bit at or above the boundary. */
	ATF_CHECK_EQ(stats.vbs_present >> BHYVE_BALLOON_STAT_COUNT, 0);
}

ATF_TC_WITHOUT_HEAD(memory_statistics_validation);
ATF_TC_BODY(memory_statistics_validation, tc)
{
	uint8_t bytes[(BHYVE_BALLOON_STATS_MAX_ENTRIES + 1) *
	    BHYVE_BALLOON_STAT_SIZE] = { 0 };
	struct virtio_balloon_stats before, stats;
	struct iovec iov;

	memset(&stats, 0xa5, sizeof(stats));
	before = stats;
	iov.iov_base = bytes;
	iov.iov_len = 9;
	ATF_CHECK_EQ(virtio_balloon_parse_stats(&iov, 1, &stats), EINVAL);
	ATF_CHECK_EQ(memcmp(&stats, &before, sizeof(stats)), 0);
	iov.iov_len = 0;
	ATF_CHECK_EQ(virtio_balloon_parse_stats(&iov, 1, &stats), EINVAL);
	iov.iov_base = NULL;
	iov.iov_len = BHYVE_BALLOON_STAT_SIZE;
	ATF_CHECK_EQ(virtio_balloon_parse_stats(&iov, 1, &stats), EINVAL);
	iov.iov_base = bytes;
	iov.iov_len = sizeof(bytes);
	ATF_CHECK_EQ(virtio_balloon_parse_stats(&iov, 1, &stats), E2BIG);
	ATF_CHECK_EQ(virtio_balloon_parse_stats(NULL, 0, &stats), EINVAL);
	ATF_CHECK_EQ(virtio_balloon_parse_stats(&iov, 1, NULL), EINVAL);
}

ATF_TC_WITHOUT_HEAD(fragmented_little_endian_pfns);
ATF_TC_BODY(fragmented_little_endian_pfns, tc)
{
	static const uint8_t bytes[] = {
		0x01, 0x00, 0x00, 0x00,
		0x78, 0x56, 0x34, 0x12,
		0xff, 0xff, 0xff, 0xff,
	};
	struct virtio_balloon_pfn_result result;
	struct callback_state state;
	struct iovec iov[] = {
		{ __DECONST(void *, bytes), 1 },
		{ __DECONST(void *, bytes + 1), 4 },
		{ __DECONST(void *, bytes + 5), 2 },
		{ __DECONST(void *, bytes + 7), 5 },
	};

	memset(&state, 0, sizeof(state));
	state.reject = UINT64_C(0x12345678) << 12;
	ATF_REQUIRE_EQ(virtio_balloon_process_pfns(iov, nitems(iov),
	    record_pfn, &state, &result), 0);
	ATF_CHECK_EQ(state.count, 3);
	ATF_CHECK_EQ(state.addresses[0], UINT64_C(0x1000));
	ATF_CHECK_EQ(state.addresses[1], UINT64_C(0x12345678000));
	ATF_CHECK_EQ(state.addresses[2], UINT64_C(0xffffffff000));
	ATF_CHECK_EQ(result.vbpr_seen, 3);
	ATF_CHECK_EQ(result.vbpr_accepted, 2);
	ATF_CHECK_EQ(result.vbpr_rejected, 1);
}

ATF_TC_WITHOUT_HEAD(malformed_vectors_are_atomic);
ATF_TC_BODY(malformed_vectors_are_atomic, tc)
{
	uint8_t bytes[BHYVE_BALLOON_REQUEST_MAX + sizeof(uint32_t)] = { 0 };
	struct virtio_balloon_pfn_result result;
	struct callback_state state;
	struct iovec iov;
	size_t count;

	memset(&state, 0, sizeof(state));
	memset(&result, 0xa5, sizeof(result));
	iov.iov_base = bytes;
	iov.iov_len = 5;
	ATF_CHECK_EQ(virtio_balloon_process_pfns(&iov, 1, record_pfn,
	    &state, &result), EINVAL);
	ATF_CHECK_EQ(state.count, 0);

	iov.iov_len = 0;
	ATF_CHECK_EQ(virtio_balloon_process_pfns(&iov, 1, record_pfn,
	    &state, &result), EINVAL);
	ATF_CHECK_EQ(state.count, 0);

	iov.iov_base = NULL;
	iov.iov_len = sizeof(uint32_t);
	ATF_CHECK_EQ(virtio_balloon_process_pfns(&iov, 1, record_pfn,
	    &state, &result), EINVAL);
	ATF_CHECK_EQ(state.count, 0);

	count = 0;
	iov.iov_base = bytes;
	iov.iov_len = BHYVE_BALLOON_REQUEST_MAX;
	ATF_REQUIRE_EQ(virtio_balloon_process_pfns(&iov, 1, count_pfn,
	    &count, &result), 0);
	ATF_CHECK_EQ(count, BHYVE_BALLOON_PFNS_PER_REQUEST);
	iov.iov_len += sizeof(uint32_t);
	ATF_CHECK_EQ(virtio_balloon_process_pfns(&iov, 1, count_pfn,
	    &count, &result), E2BIG);
	ATF_CHECK_EQ(count, BHYVE_BALLOON_PFNS_PER_REQUEST);
}

ATF_TC_WITHOUT_HEAD(host_page_tracker);
ATF_TC_BODY(host_page_tracker, tc)
{
	struct virtio_balloon_page_tracker tracker;
	uint8_t bitmap[4];
	uint64_t discard_gpa, undiscard_gpa;
	size_t discard_len, required, undiscard_len;
	bool ready;

	ATF_REQUIRE_EQ(virtio_balloon_tracker_required(0x8000, 0x10000,
	    0x8000, &required), 0);
	ATF_REQUIRE_EQ(required, 2);
	ATF_REQUIRE_EQ(virtio_balloon_tracker_init(&tracker, 0x8000,
	    0x10000, 0x8000, 0x4000, bitmap, sizeof(bitmap)), 0);

	for (uint64_t gpa = 0; gpa < 0x3000; gpa += 0x1000) {
		ATF_REQUIRE_EQ(virtio_balloon_tracker_inflate(&tracker, gpa,
		    &discard_gpa, &discard_len, &ready), 0);
		ATF_CHECK(!ready);
	}
	ATF_REQUIRE_EQ(virtio_balloon_tracker_deflate(&tracker, 0x1000,
	    &undiscard_gpa, &undiscard_len), 0);
	ATF_CHECK_EQ(undiscard_len, 0);
	ATF_REQUIRE_EQ(virtio_balloon_tracker_inflate(&tracker, 0x1000,
	    &discard_gpa, &discard_len, &ready), 0);
	ATF_CHECK(!ready);
	ATF_REQUIRE_EQ(virtio_balloon_tracker_inflate(&tracker, 0x3000,
	    &discard_gpa, &discard_len, &ready), 0);
	ATF_CHECK(ready);
	ATF_CHECK_EQ(discard_gpa, 0);
	ATF_CHECK_EQ(discard_len, 0x4000);

	ATF_REQUIRE_EQ(virtio_balloon_tracker_deflate(&tracker, 0x1000,
	    &undiscard_gpa, &undiscard_len), 0);
	ATF_CHECK_EQ(undiscard_gpa, 0);
	ATF_CHECK_EQ(undiscard_len, 0x4000);
	ATF_REQUIRE_EQ(virtio_balloon_tracker_inflate(&tracker, 0,
	    &discard_gpa, &discard_len, &ready), 0);
	ATF_CHECK(!ready);
	ATF_REQUIRE_EQ(virtio_balloon_tracker_inflate(&tracker, 0x1000,
	    &discard_gpa, &discard_len, &ready), 0);
	ATF_CHECK(ready);

	/* The MMIO hole cannot complete a host-page ownership group. */
	ATF_CHECK_EQ(virtio_balloon_tracker_inflate(&tracker, 0x8000,
	    &discard_gpa, &discard_len, &ready), EFAULT);
	ATF_CHECK_EQ(virtio_balloon_tracker_deflate(&tracker, 0x8000,
	    &undiscard_gpa, &undiscard_len), EFAULT);

	for (uint64_t gpa = 0x10000; gpa < 0x14000; gpa += 0x1000) {
		ATF_REQUIRE_EQ(virtio_balloon_tracker_inflate(&tracker, gpa,
		    &discard_gpa, &discard_len, &ready), 0);
	}
	ATF_CHECK(ready);
	ATF_CHECK_EQ(discard_gpa, UINT64_C(0x10000));
	ATF_CHECK_EQ(discard_len, 0x4000);
}

ATF_TC_WITHOUT_HEAD(host_page_tracker_granules);
ATF_TC_BODY(host_page_tracker_granules, tc)
{
	struct virtio_balloon_page_tracker tracker;
	uint8_t bitmap[2];
	uint64_t discard_gpa;
	size_t discard_len;
	bool ready;

	ATF_REQUIRE_EQ(virtio_balloon_tracker_init(&tracker, 0x10000, 0,
	    0, 0x1000, bitmap, sizeof(bitmap)), 0);
	ATF_REQUIRE_EQ(virtio_balloon_tracker_inflate(&tracker, 0x5000,
	    &discard_gpa, &discard_len, &ready), 0);
	ATF_CHECK(ready);
	ATF_CHECK_EQ(discard_gpa, UINT64_C(0x5000));
	ATF_CHECK_EQ(discard_len, 0x1000);

	ATF_REQUIRE_EQ(virtio_balloon_tracker_init(&tracker, 0x10000, 0,
	    0, 0x10000, bitmap, sizeof(bitmap)), 0);
	for (uint64_t gpa = 0; gpa < 0x10000; gpa += 0x1000) {
		ATF_REQUIRE_EQ(virtio_balloon_tracker_inflate(&tracker, gpa,
		    &discard_gpa, &discard_len, &ready), 0);
		ATF_CHECK_EQ(ready, gpa == 0xf000);
	}
	ATF_CHECK_EQ(discard_gpa, 0);
	ATF_CHECK_EQ(discard_len, 0x10000);
	ATF_REQUIRE_EQ(virtio_balloon_tracker_deflate(&tracker, 0x5000,
	    &discard_gpa, &discard_len), 0);
	ATF_CHECK_EQ(discard_gpa, 0);
	ATF_CHECK_EQ(discard_len, 0x10000);
}

ATF_TC_WITHOUT_HEAD(duplicate_pfns_are_idempotent);
ATF_TC_BODY(duplicate_pfns_are_idempotent, tc)
{
	struct virtio_balloon_page_tracker tracker;
	uint8_t bitmap[1];
	uint64_t range_gpa;
	size_t range_len;
	bool changed, ready;

	ATF_REQUIRE_EQ(virtio_balloon_tracker_init(&tracker, 0x4000, 0, 0,
	    0x4000, bitmap, sizeof(bitmap)), 0);
	for (uint64_t gpa = 0; gpa < 0x4000; gpa += 0x1000) {
		ATF_REQUIRE_EQ(virtio_balloon_tracker_inflate_transition(
		    &tracker, gpa, &range_gpa, &range_len, &ready,
		    &changed), 0);
		ATF_REQUIRE(changed);
		ATF_CHECK_EQ(ready, gpa == 0x3000);
	}
	ATF_CHECK_EQ(range_gpa, 0);
	ATF_CHECK_EQ(range_len, 0x4000);

	/*
	 * Once the native host page is complete, a duplicate PFN must not
	 * advertise that extent to the backend for a second discard.
	 */
	range_gpa = UINT64_MAX;
	range_len = SIZE_MAX;
	ATF_REQUIRE_EQ(virtio_balloon_tracker_inflate_transition(&tracker,
	    0x1000, &range_gpa, &range_len, &ready, &changed), 0);
	ATF_CHECK(!changed);
	ATF_CHECK(!ready);
	ATF_CHECK_EQ(range_gpa, 0);
	ATF_CHECK_EQ(range_len, 0);

	ATF_REQUIRE_EQ(virtio_balloon_tracker_deflate_transition(&tracker,
	    0x1000, &range_gpa, &range_len, &changed), 0);
	ATF_REQUIRE(changed);
	ATF_CHECK_EQ(range_gpa, 0);
	ATF_CHECK_EQ(range_len, 0x4000);
	range_gpa = UINT64_MAX;
	range_len = SIZE_MAX;
	ATF_REQUIRE_EQ(virtio_balloon_tracker_deflate_transition(&tracker,
	    0x1000, &range_gpa, &range_len, &changed), 0);
	ATF_CHECK(!changed);
	ATF_CHECK_EQ(range_gpa, 0);
	ATF_CHECK_EQ(range_len, 0);
}

ATF_TC_WITHOUT_HEAD(tracker_release_all_is_transactional);
ATF_TC_BODY(tracker_release_all_is_transactional, tc)
{
	struct virtio_balloon_page_tracker tracker;
	struct range_state ranges;
	uint8_t bitmap[2];
	uint64_t discard_gpa;
	size_t discard_len;
	bool ready;

	ATF_REQUIRE_EQ(virtio_balloon_tracker_init(&tracker, 0x8000, 0x10000,
	    0x4000, 0x4000, bitmap, sizeof(bitmap)), 0);
	for (uint64_t gpa = 0; gpa < 0x8000; gpa += 0x1000) {
		ATF_REQUIRE_EQ(virtio_balloon_tracker_inflate(&tracker, gpa,
		    &discard_gpa, &discard_len, &ready), 0);
	}
	/* A partial high-memory host page was never discarded. */
	ATF_REQUIRE_EQ(virtio_balloon_tracker_inflate(&tracker, 0x10000,
	    &discard_gpa, &discard_len, &ready), 0);
	ATF_CHECK(!ready);

	memset(&ranges, 0, sizeof(ranges));
	ranges.fail_at = 2;
	ATF_CHECK_EQ(virtio_balloon_tracker_release_all(&tracker,
	    record_range, &ranges), EIO);
	ATF_CHECK_EQ(ranges.count, 2);
	for (size_t i = 0; i < sizeof(bitmap); i++)
		ATF_CHECK(bitmap[i] != 0);

	memset(&ranges, 0, sizeof(ranges));
	ATF_REQUIRE_EQ(virtio_balloon_tracker_release_all(&tracker,
	    record_range, &ranges), 0);
	ATF_CHECK_EQ(ranges.count, 2);
	ATF_CHECK_EQ(ranges.addresses[0], 0);
	ATF_CHECK_EQ(ranges.addresses[1], UINT64_C(0x4000));
	ATF_CHECK_EQ(ranges.lengths[0], 0x4000);
	ATF_CHECK_EQ(ranges.lengths[1], 0x4000);
	for (size_t i = 0; i < sizeof(bitmap); i++)
		ATF_CHECK_EQ(bitmap[i], 0);

	ATF_CHECK_EQ(virtio_balloon_tracker_release_all(NULL, record_range,
	    &ranges), EINVAL);
	ATF_CHECK_EQ(virtio_balloon_tracker_release_all(&tracker, NULL,
	    &ranges), EINVAL);
}

ATF_TC_WITHOUT_HEAD(tracker_validation);
ATF_TC_BODY(tracker_validation, tc)
{
	struct virtio_balloon_page_tracker tracker;
	uint8_t bitmap[2];
	size_t required;

	ATF_CHECK_EQ(virtio_balloon_tracker_required(1, 0, 0, &required),
	    EINVAL);
	ATF_CHECK_EQ(virtio_balloon_tracker_required(0, 1, 0, &required),
	    EINVAL);
	ATF_CHECK_EQ(virtio_balloon_tracker_required(0, 0, 1, &required),
	    EINVAL);
	ATF_CHECK_EQ(virtio_balloon_tracker_required(0x4000, 0x2000,
	    0x1000, &required), EINVAL);
	ATF_CHECK_EQ(virtio_balloon_tracker_required(0, UINT64_MAX - 0xfff,
	    0x2000, &required), EINVAL);
	ATF_CHECK_EQ(virtio_balloon_tracker_init(&tracker, 0x4000, 0,
	    0, 0x1000, NULL, 0), EINVAL);
	ATF_CHECK_EQ(virtio_balloon_tracker_init(&tracker, 0x4000, 0,
	    0, 0x3000, bitmap, sizeof(bitmap)), EINVAL);
	ATF_CHECK_EQ(virtio_balloon_tracker_init(&tracker, 0x4000, 0,
	    0, 0x4000, NULL, 0), EINVAL);
	ATF_CHECK_EQ(virtio_balloon_tracker_init(&tracker, 0x5000, 0,
	    0, 0x4000, bitmap, sizeof(bitmap)), EINVAL);
	ATF_CHECK_EQ(virtio_balloon_tracker_init(&tracker, 0x4000, 0x9000,
	    0x4000, 0x4000, bitmap, sizeof(bitmap)), EINVAL);
}

ATF_TC_WITHOUT_HEAD(accounting_bounds_and_reset);
ATF_TC_BODY(accounting_bounds_and_reset, tc)
{
	struct virtio_balloon_accounting accounting;
	bool changed;

	ATF_REQUIRE_EQ(virtio_balloon_accounting_init(&accounting, 0x10000,
	    4), 0);
	ATF_CHECK_EQ(accounting.vba_total_pages, 16);
	ATF_CHECK_EQ(accounting.vba_target_pages, 4);
	ATF_CHECK_EQ(accounting.vba_actual_pages, 0);

	ATF_REQUIRE_EQ(virtio_balloon_accounting_set_target(&accounting, 4,
	    &changed), 0);
	ATF_CHECK(!changed);
	ATF_REQUIRE_EQ(virtio_balloon_accounting_set_target(&accounting, 8,
	    &changed), 0);
	ATF_CHECK(changed);
	ATF_CHECK_EQ(virtio_balloon_accounting_set_target(&accounting, 17,
	    &changed), ERANGE);
	ATF_CHECK_EQ(accounting.vba_target_pages, 8);

	ATF_REQUIRE_EQ(virtio_balloon_accounting_set_actual(&accounting, 9),
	    0);
	ATF_CHECK_EQ(virtio_balloon_accounting_set_actual(&accounting, 17),
	    ERANGE);
	virtio_balloon_accounting_reset(&accounting);
	ATF_CHECK_EQ(accounting.vba_target_pages, 8);
	ATF_CHECK_EQ(accounting.vba_actual_pages, 0);

	ATF_CHECK_EQ(virtio_balloon_accounting_init(&accounting, 1, 0),
	    EINVAL);
	ATF_CHECK_EQ(virtio_balloon_accounting_init(&accounting,
	    ((uint64_t)UINT32_MAX + 1) << 12, 0), ERANGE);
}

ATF_TC_WITHOUT_HEAD(publication_aliases_are_rejected);
ATF_TC_BODY(publication_aliases_are_rejected, tc)
{
	struct virtio_balloon_page_tracker tracker, tracker_before;
	struct virtio_balloon_accounting accounting;
	struct virtio_balloon_pfn_result pfn_result;
	struct virtio_balloon_stats stats;
	struct callback_state callback;
	struct iovec iov[BHYVE_BALLOON_MAX_IOV + 1];
	uint8_t bitmap[2], pfn[sizeof(uint32_t)], stat[BHYVE_BALLOON_STAT_SIZE];
	uint64_t gpa;
	size_t length;
	bool ready, changed;

	memset(&tracker, 0xa5, sizeof(tracker));
	tracker_before = tracker;
	ATF_CHECK_EQ(virtio_balloon_tracker_init(&tracker, 0x8000, 0, 0,
	    0x4000, (uint8_t *)(void *)&tracker, sizeof(tracker)), EINVAL);
	ATF_CHECK(memcmp(&tracker, &tracker_before, sizeof(tracker)) == 0);
	memset(bitmap, 0, sizeof(bitmap));
	ATF_REQUIRE_EQ(virtio_balloon_tracker_init(&tracker, 0x8000, 0, 0,
	    0x4000, bitmap, sizeof(bitmap)), 0);

	gpa = 91;
	length = 92;
	ready = true;
	changed = false;
	ATF_CHECK_EQ(virtio_balloon_tracker_inflate_transition(&tracker, 0,
	    (uint64_t *)(void *)&tracker, &length, &ready, &changed), EINVAL);
	ATF_CHECK_EQ(bitmap[0], 0);
	ATF_CHECK_EQ(length, 92);
	ATF_CHECK(ready);
	ATF_CHECK(!changed);
	ATF_CHECK_EQ(virtio_balloon_tracker_inflate_transition(&tracker, 0,
	    &gpa, (size_t *)(void *)&gpa, &ready, &changed), EINVAL);
	ATF_CHECK_EQ(bitmap[0], 0);
	ATF_CHECK_EQ(virtio_balloon_tracker_inflate_transition(&tracker, 0,
	    &gpa, &length, &ready, (bool *)(void *)bitmap), EINVAL);
	ATF_CHECK_EQ(bitmap[0], 0);
	ATF_REQUIRE_EQ(virtio_balloon_tracker_inflate_transition(&tracker, 0,
	    &gpa, &length, &ready, &changed), 0);
	ATF_CHECK(changed);
	ATF_CHECK_EQ(bitmap[0], 1);

	ATF_CHECK_EQ(virtio_balloon_tracker_deflate_transition(&tracker, 0,
	    (uint64_t *)(void *)&tracker, &length, &changed), EINVAL);
	ATF_CHECK_EQ(bitmap[0], 1);
	ATF_CHECK_EQ(virtio_balloon_tracker_deflate_transition(&tracker, 0,
	    &gpa, (size_t *)(void *)&gpa, &changed), EINVAL);
	ATF_CHECK_EQ(bitmap[0], 1);
	ATF_REQUIRE_EQ(virtio_balloon_tracker_deflate_transition(&tracker, 0,
	    &gpa, &length, &changed), 0);
	ATF_CHECK(changed);
	ATF_CHECK_EQ(bitmap[0], 0);

	ATF_REQUIRE_EQ(virtio_balloon_accounting_init(&accounting, 0x10000,
	    4), 0);
	ATF_CHECK_EQ(virtio_balloon_accounting_set_target(&accounting, 8,
	    (bool *)(void *)&accounting), EINVAL);
	ATF_CHECK_EQ(accounting.vba_target_pages, 4);

	memset(iov, 0, sizeof(iov));
	le32enc(pfn, 1);
	iov[0].iov_base = pfn;
	iov[0].iov_len = sizeof(pfn);
	memset(&callback, 0, sizeof(callback));
	ATF_CHECK_EQ(virtio_balloon_process_pfns(iov, 1, record_pfn,
	    &callback, (struct virtio_balloon_pfn_result *)(void *)iov),
	    EINVAL);
	ATF_CHECK_EQ(callback.count, 0);
	ATF_CHECK_EQ(virtio_balloon_process_pfns(iov, 1, record_pfn,
	    &callback, (struct virtio_balloon_pfn_result *)(void *)pfn),
	    EINVAL);
	ATF_CHECK_EQ(callback.count, 0);
	ATF_CHECK_EQ(virtio_balloon_process_pfns(iov, nitems(iov), record_pfn,
	    &callback, &pfn_result), EINVAL);
	ATF_CHECK_EQ(callback.count, 0);

	memset(stat, 0, sizeof(stat));
	iov[0].iov_base = stat;
	iov[0].iov_len = sizeof(stat);
	ATF_CHECK_EQ(virtio_balloon_parse_stats(iov, 1,
	    (struct virtio_balloon_stats *)(void *)iov), EINVAL);
	ATF_CHECK_EQ(virtio_balloon_parse_stats(iov, 1,
	    (struct virtio_balloon_stats *)(void *)stat), EINVAL);
	ATF_CHECK_EQ(virtio_balloon_parse_stats(iov, nitems(iov), &stats),
	    EINVAL);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, fragmented_memory_statistics);
	ATF_TP_ADD_TC(tp, statistics_tag_boundary);
	ATF_TP_ADD_TC(tp, memory_statistics_validation);
	ATF_TP_ADD_TC(tp, fragmented_little_endian_pfns);
	ATF_TP_ADD_TC(tp, malformed_vectors_are_atomic);
	ATF_TP_ADD_TC(tp, host_page_tracker);
	ATF_TP_ADD_TC(tp, host_page_tracker_granules);
	ATF_TP_ADD_TC(tp, duplicate_pfns_are_idempotent);
	ATF_TP_ADD_TC(tp, tracker_release_all_is_transactional);
	ATF_TP_ADD_TC(tp, tracker_validation);
	ATF_TP_ADD_TC(tp, accounting_bounds_and_reset);
	ATF_TP_ADD_TC(tp, publication_aliases_are_rejected);
	return (atf_no_error());
}
