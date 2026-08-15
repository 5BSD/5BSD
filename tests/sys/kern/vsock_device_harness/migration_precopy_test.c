/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <atf-c.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define vm_dirty_log_request mock_vm_dirty_log_request
#include "../../../../sys/dev/vmm/vmm_dirty_log.c"
#include "../../../../sys/dev/vmm/vmm_dirty_log_request.c"
#include "../../../../usr.sbin/bhyve/migration_dirty.c"

static int migration_preflight_error;
int pci_migration_precopy_validate(void);

int
pci_migration_precopy_validate(void)
{

	return (migration_preflight_error);
}

#include "../../../../usr.sbin/bhyve/migration_precopy.c"
#undef vm_dirty_log_request

int
vm_dirty_log_result_validate(const struct vmm_dirty_log_result *result,
    size_t buffer_bytes)
{

	return (vmm_dirty_log_result_validate(result, buffer_bytes));
}

static struct vmctx *const owner = (struct vmctx *)(uintptr_t)0x1000;

struct cpu_mock {
	uint8_t bitmap[2];
	uint64_t identity;
	uint64_t map_generation;
	uint64_t dirty_generation;
	int enable_error;
	int collect_error;
	int disable_error;
	unsigned int enable_calls;
	unsigned int collect_calls;
	unsigned int disable_calls;
	bool enabled;
	pthread_mutex_t block_lock;
	pthread_cond_t block_cv;
	bool block_collect;
	bool collect_entered;
	bool collect_release;
};

static int
cpu_enable(void *arg, uint64_t gpa, uint64_t length)
{
	struct cpu_mock *mock;

	mock = arg;
	mock->enable_calls++;
	if (mock->enable_error != 0)
		return (mock->enable_error);
	if (gpa != 0 || length != 16 * 4096)
		return (EINVAL);
	mock->enabled = true;
	return (0);
}

static int
cpu_collect(void *arg, uint64_t gpa, uint64_t length,
    enum migration_dirty_collect_mode mode, uint8_t *bitmap,
    size_t bitmap_bytes, struct migration_precopy_cpu_generation *generation)
{
	struct cpu_mock *mock;

	mock = arg;
	mock->collect_calls++;
	if (mock->collect_error != 0)
		return (mock->collect_error);
	if (!mock->enabled || gpa != 0 || length != 16 * 4096 ||
	    bitmap_bytes != sizeof(mock->bitmap))
		return (EINVAL);
	if (mock->block_collect) {
		pthread_mutex_lock(&mock->block_lock);
		mock->collect_entered = true;
		pthread_cond_broadcast(&mock->block_cv);
		while (!mock->collect_release)
			pthread_cond_wait(&mock->block_cv, &mock->block_lock);
		pthread_mutex_unlock(&mock->block_lock);
	}
	memcpy(bitmap, mock->bitmap, bitmap_bytes);
	*generation = (struct migration_precopy_cpu_generation) {
		.identity = mock->identity,
		.map_generation = mock->map_generation,
		.dirty_generation = mock->dirty_generation,
	};
	if (mode == MIGRATION_DIRTY_CLEAR) {
		memset(mock->bitmap, 0, sizeof(mock->bitmap));
		mock->dirty_generation++;
	}
	return (0);
}

static int
cpu_disable(void *arg)
{
	struct cpu_mock *mock;

	mock = arg;
	mock->disable_calls++;
	if (mock->disable_error != 0)
		return (mock->disable_error);
	mock->enabled = false;
	return (0);
}

static const struct migration_precopy_cpu_ops cpu_ops = {
	.enable = cpu_enable,
	.collect = cpu_collect,
	.disable = cpu_disable,
};

static struct cpu_mock
valid_cpu(void)
{

	return ((struct cpu_mock) {
		.identity = 7,
		.map_generation = 11,
		.dirty_generation = 13,
	});
}

struct collect_thread_arg {
	struct cpu_mock *mock;
	struct migration_precopy_generation generation;
	uint8_t bitmap[2];
	int error;
};

static void *
collect_thread(void *arg)
{
	struct collect_thread_arg *thread;

	thread = arg;
	thread->error = migration_precopy_collect_with_ops(owner, 0, 16 * 4096,
	    MIGRATION_DIRTY_OBSERVE, thread->bitmap, sizeof(thread->bitmap),
	    &thread->generation, &cpu_ops, thread->mock);
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(enable_rollback_is_fail_closed);
ATF_TC_BODY(enable_rollback_is_fail_closed, tc)
{
	struct cpu_mock mock;
	size_t bytes;

	(void)tc;
	mock = valid_cpu();
	mock.enable_error = EIO;
	ATF_CHECK_EQ(migration_precopy_enable_with_ops(owner, 0, 16 * 4096,
	    &cpu_ops, &mock), EIO);
	ATF_CHECK_EQ(migration_dirty_bitmap_bytes(owner, &bytes), ENOENT);

	mock = valid_cpu();
	ATF_REQUIRE_EQ(migration_dirty_enable(owner, 0, 16 * 4096), 0);
	ATF_CHECK_EQ(migration_precopy_enable_with_ops(owner, 0, 16 * 4096,
	    &cpu_ops, &mock), EBUSY);
	ATF_CHECK_EQ(mock.disable_calls, 1);
	ATF_CHECK(!mock.enabled);
	ATF_REQUIRE_EQ(migration_dirty_disable(owner), 0);

	mock = valid_cpu();
	mock.disable_error = EBUSY;
	ATF_REQUIRE_EQ(migration_dirty_enable(owner, 0, 16 * 4096), 0);
	ATF_CHECK_EQ(migration_precopy_enable_with_ops(owner, 0, 16 * 4096,
	    &cpu_ops, &mock), EPROTO);
	ATF_REQUIRE_EQ(migration_dirty_disable(owner), 0);
	mock.disable_error = 0;
	ATF_REQUIRE_EQ(migration_precopy_disable_with_ops(owner, &cpu_ops,
	    &mock), 0);
}

ATF_TC_WITHOUT_HEAD(iterative_clear_keeps_device_dirties_cumulative);
ATF_TC_BODY(iterative_clear_keeps_device_dirties_cumulative, tc)
{
	struct migration_precopy_generation generation;
	struct cpu_mock mock;
	uint8_t bitmap[2];

	(void)tc;
	mock = valid_cpu();
	mock.bitmap[0] = 0x04;
	ATF_REQUIRE_EQ(migration_precopy_enable_with_ops(owner, 0, 16 * 4096,
	    &cpu_ops, &mock), 0);
	ATF_REQUIRE_EQ(migration_dirty_mark(owner, 4096, 1), 0);
	memset(bitmap, 0xa5, sizeof(bitmap));
	memset(&generation, 0xa5, sizeof(generation));
	ATF_REQUIRE_EQ(migration_precopy_collect_with_ops(owner, 0, 16 * 4096,
	    MIGRATION_DIRTY_CLEAR, bitmap, sizeof(bitmap), &generation,
	    &cpu_ops, &mock), 0);
	ATF_CHECK_EQ(bitmap[0], 0x06);
	ATF_CHECK_EQ(bitmap[1], 0x00);
	ATF_CHECK_EQ(generation.cpu_identity, 7);
	ATF_CHECK_EQ(generation.cpu_map_generation, 11);
	ATF_CHECK_EQ(generation.cpu_dirty_generation, 13);
	ATF_CHECK(generation.device_identity != 0);
	ATF_CHECK_EQ(generation.device_dirty_generation, 1);
	ATF_CHECK_EQ(generation.cpu_mode, MIGRATION_DIRTY_CLEAR);
	ATF_CHECK_EQ(generation.device_mode, MIGRATION_DIRTY_OBSERVE);

	ATF_REQUIRE_EQ(migration_dirty_mark(owner, 3 * 4096, 1), 0);
	mock.bitmap[0] = 0x10;
	ATF_REQUIRE_EQ(migration_precopy_collect_with_ops(owner, 0, 16 * 4096,
	    MIGRATION_DIRTY_CLEAR, bitmap, sizeof(bitmap), &generation,
	    &cpu_ops, &mock), 0);
	/* Page one remains set: a pre-cut asynchronous DMA lease may still use it. */
	ATF_CHECK_EQ(bitmap[0], 0x1a);
	ATF_CHECK_EQ(generation.device_dirty_generation, 1);
	ATF_REQUIRE_EQ(migration_precopy_disable_with_ops(owner, &cpu_ops,
	    &mock), 0);
}

ATF_TC_WITHOUT_HEAD(cpu_failure_aborts_device_cut_atomically);
ATF_TC_BODY(cpu_failure_aborts_device_cut_atomically, tc)
{
	struct migration_precopy_generation generation, before_generation;
	struct cpu_mock mock;
	uint8_t bitmap[2], before_bitmap[2];

	(void)tc;
	mock = valid_cpu();
	ATF_REQUIRE_EQ(migration_precopy_enable_with_ops(owner, 0, 16 * 4096,
	    &cpu_ops, &mock), 0);
	ATF_REQUIRE_EQ(migration_dirty_mark(owner, 0, 1), 0);
	mock.collect_error = EIO;
	memset(bitmap, 0xa5, sizeof(bitmap));
	memset(&generation, 0x5a, sizeof(generation));
	memcpy(before_bitmap, bitmap, sizeof(bitmap));
	before_generation = generation;
	ATF_CHECK_EQ(migration_precopy_collect_with_ops(owner, 0, 16 * 4096,
	    MIGRATION_DIRTY_OBSERVE, bitmap, sizeof(bitmap), &generation,
	    &cpu_ops, &mock), EIO);
	ATF_CHECK_EQ(memcmp(bitmap, before_bitmap, sizeof(bitmap)), 0);
	ATF_CHECK_EQ(memcmp(&generation, &before_generation,
	    sizeof(generation)), 0);

	mock.collect_error = 0;
	ATF_REQUIRE_EQ(migration_precopy_collect_with_ops(owner, 0, 16 * 4096,
	    MIGRATION_DIRTY_OBSERVE, bitmap, sizeof(bitmap), &generation,
	    &cpu_ops, &mock), 0);
	ATF_CHECK_EQ(bitmap[0], 0x01);
	ATF_REQUIRE_EQ(migration_precopy_disable_with_ops(owner, &cpu_ops,
	    &mock), 0);
}

ATF_TC_WITHOUT_HEAD(clear_failure_is_cleanup_only);
ATF_TC_BODY(clear_failure_is_cleanup_only, tc)
{
	struct migration_precopy_generation generation;
	struct cpu_mock mock;
	uint8_t bitmap[2];

	(void)tc;
	mock = valid_cpu();
	ATF_REQUIRE_EQ(migration_precopy_enable_with_ops(owner, 0, 16 * 4096,
	    &cpu_ops, &mock), 0);
	ATF_REQUIRE_EQ(migration_dirty_mark(owner, 0, 1), 0);
	mock.collect_error = EIO;
	ATF_CHECK_EQ(migration_precopy_collect_with_ops(owner, 0, 16 * 4096,
	    MIGRATION_DIRTY_CLEAR, bitmap, sizeof(bitmap), &generation,
	    &cpu_ops, &mock), EIO);
	mock.collect_error = 0;
	ATF_CHECK_EQ(migration_precopy_collect_with_ops(owner, 0, 16 * 4096,
	    MIGRATION_DIRTY_OBSERVE, bitmap, sizeof(bitmap), &generation,
	    &cpu_ops, &mock), EPROTO);
	ATF_REQUIRE_EQ(migration_precopy_disable_with_ops(owner, &cpu_ops,
	    &mock), 0);
}

ATF_TC_WITHOUT_HEAD(partial_disable_is_retryable_cleanup);
ATF_TC_BODY(partial_disable_is_retryable_cleanup, tc)
{
	struct migration_precopy_generation generation;
	struct cpu_mock mock;
	uint8_t bitmap[2];

	(void)tc;
	mock = valid_cpu();
	ATF_REQUIRE_EQ(migration_precopy_enable_with_ops(owner, 0, 16 * 4096,
	    &cpu_ops, &mock), 0);
	mock.disable_error = EIO;
	ATF_CHECK_EQ(migration_precopy_disable_with_ops(owner, &cpu_ops,
	    &mock), EIO);
	ATF_CHECK_EQ(migration_precopy_collect_with_ops(owner, 0, 16 * 4096,
	    MIGRATION_DIRTY_OBSERVE, bitmap, sizeof(bitmap), &generation,
	    &cpu_ops, &mock), EPROTO);
	mock.disable_error = 0;
	ATF_REQUIRE_EQ(migration_precopy_disable_with_ops(owner, &cpu_ops,
	    &mock), 0);
	ATF_REQUIRE_EQ(migration_precopy_enable_with_ops(owner, 0, 16 * 4096,
	    &cpu_ops, &mock), 0);
	ATF_REQUIRE_EQ(migration_precopy_disable_with_ops(owner, &cpu_ops,
	    &mock), 0);
}

ATF_TC_WITHOUT_HEAD(concurrent_lifecycle_is_serialized);
ATF_TC_BODY(concurrent_lifecycle_is_serialized, tc)
{
	struct migration_precopy_generation generation;
	struct collect_thread_arg thread_arg;
	struct cpu_mock mock;
	pthread_t thread;
	uint8_t bitmap[2];

	(void)tc;
	mock = valid_cpu();
	ATF_REQUIRE_EQ(pthread_mutex_init(&mock.block_lock, NULL), 0);
	ATF_REQUIRE_EQ(pthread_cond_init(&mock.block_cv, NULL), 0);
	mock.block_collect = true;
	ATF_REQUIRE_EQ(migration_precopy_enable_with_ops(owner, 0, 16 * 4096,
	    &cpu_ops, &mock), 0);
	memset(&thread_arg, 0, sizeof(thread_arg));
	thread_arg.mock = &mock;
	ATF_REQUIRE_EQ(pthread_create(&thread, NULL, collect_thread,
	    &thread_arg), 0);
	pthread_mutex_lock(&mock.block_lock);
	while (!mock.collect_entered)
		pthread_cond_wait(&mock.block_cv, &mock.block_lock);
	pthread_mutex_unlock(&mock.block_lock);

	ATF_CHECK_EQ(migration_precopy_collect_with_ops(owner, 0, 16 * 4096,
	    MIGRATION_DIRTY_OBSERVE, bitmap, sizeof(bitmap), &generation,
	    &cpu_ops, &mock), EBUSY);
	ATF_CHECK_EQ(migration_precopy_disable_with_ops(owner, &cpu_ops,
	    &mock), EBUSY);
	ATF_CHECK_EQ(migration_precopy_enable_with_ops(owner, 0, 16 * 4096,
	    &cpu_ops, &mock), EBUSY);

	pthread_mutex_lock(&mock.block_lock);
	mock.collect_release = true;
	pthread_cond_broadcast(&mock.block_cv);
	pthread_mutex_unlock(&mock.block_lock);
	ATF_REQUIRE_EQ(pthread_join(thread, NULL), 0);
	ATF_CHECK_EQ(thread_arg.error, 0);
	ATF_REQUIRE_EQ(migration_precopy_disable_with_ops(owner, &cpu_ops,
	    &mock), 0);
	ATF_REQUIRE_EQ(pthread_cond_destroy(&mock.block_cv), 0);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&mock.block_lock), 0);
}

ATF_TC_WITHOUT_HEAD(rejects_alias_and_invalid_cpu_metadata);
ATF_TC_BODY(rejects_alias_and_invalid_cpu_metadata, tc)
{
	union {
		struct migration_precopy_generation generation;
		uint8_t bitmap[sizeof(struct migration_precopy_generation)];
	} alias;
	struct migration_precopy_generation generation;
	struct cpu_mock mock;
	uint8_t bitmap[2];

	(void)tc;
	mock = valid_cpu();
	ATF_REQUIRE_EQ(migration_precopy_enable_with_ops(owner, 0, 16 * 4096,
	    &cpu_ops, &mock), 0);
	ATF_CHECK_EQ(migration_precopy_collect_with_ops(owner, 0, 16 * 4096,
	    MIGRATION_DIRTY_CLEAR, alias.bitmap, 2, &alias.generation,
	    &cpu_ops, &mock), EINVAL);
	mock.identity = 0;
	ATF_CHECK_EQ(migration_precopy_collect_with_ops(owner, 0, 16 * 4096,
	    MIGRATION_DIRTY_CLEAR, bitmap, sizeof(bitmap), &generation,
	    &cpu_ops, &mock), EPROTO);
	mock.identity = 7;
	ATF_CHECK_EQ(migration_precopy_collect_with_ops(owner, 0, 16 * 4096,
	    MIGRATION_DIRTY_OBSERVE, bitmap, sizeof(bitmap), &generation,
	    &cpu_ops, &mock), EPROTO);
	ATF_REQUIRE_EQ(migration_precopy_disable_with_ops(owner, &cpu_ops,
	    &mock), 0);
}

static bool default_enabled;
static uint64_t default_result_gpa_delta;

int
mock_vm_dirty_log_request(struct vmctx *ctx,
    const struct vmm_dirty_log_request *request)
{
	struct vmm_dirty_log_result *result;
	void *output;
	uint8_t *publication;

	if (ctx != owner) {
		errno = EINVAL;
		return (-1);
	}
	if (request->operation == VMM_DIRTY_LOG_REQUEST_ENABLE) {
		default_enabled = true;
		return (0);
	}
	if (request->operation == VMM_DIRTY_LOG_REQUEST_DISABLE) {
		default_enabled = false;
		return (0);
	}
	if (!default_enabled) {
		errno = ENOENT;
		return (-1);
	}
	output = (void *)(uintptr_t)request->output_address;
	result = output;
	publication = output;
	if (vmm_dirty_log_result_encode(request, 17, 19, 23, result) != 0) {
		errno = EINVAL;
		return (-1);
	}
	result->gpa += default_result_gpa_delta;
	publication[result->bitmap_offset] = 0x80;
	publication[result->bitmap_offset + 1] = 0x01;
	return (0);
}

ATF_TC_WITHOUT_HEAD(default_adapter_uses_self_describing_publication);
ATF_TC_BODY(default_adapter_uses_self_describing_publication, tc)
{
	struct migration_precopy_generation generation;
	uint8_t bitmap[2];

	(void)tc;
	migration_preflight_error = 0;
	default_enabled = false;
	default_result_gpa_delta = 0;
	ATF_REQUIRE_EQ(migration_precopy_enable(owner, 0, 16 * 4096), 0);
	ATF_REQUIRE_EQ(migration_precopy_collect(owner, 0, 16 * 4096,
	    MIGRATION_DIRTY_CLEAR, bitmap, sizeof(bitmap), &generation), 0);
	ATF_CHECK_EQ(bitmap[0], 0x80);
	ATF_CHECK_EQ(bitmap[1], 0x01);
	ATF_CHECK_EQ(generation.cpu_identity, 17);
	ATF_CHECK_EQ(generation.cpu_map_generation, 19);
	ATF_CHECK_EQ(generation.cpu_dirty_generation, 23);
	ATF_REQUIRE_EQ(migration_precopy_disable(owner), 0);
}

ATF_TC_WITHOUT_HEAD(default_adapter_rejects_mismatched_publication);
ATF_TC_BODY(default_adapter_rejects_mismatched_publication, tc)
{
	struct migration_precopy_generation generation;
	uint8_t bitmap[2];

	(void)tc;
	migration_preflight_error = 0;
	default_enabled = false;
	default_result_gpa_delta = 4096;
	ATF_REQUIRE_EQ(migration_precopy_enable(owner, 0, 16 * 4096), 0);
	ATF_CHECK_EQ(migration_precopy_collect(owner, 0, 16 * 4096,
	    MIGRATION_DIRTY_CLEAR, bitmap, sizeof(bitmap), &generation), EPROTO);
	default_result_gpa_delta = 0;
	ATF_CHECK_EQ(migration_precopy_collect(owner, 0, 16 * 4096,
	    MIGRATION_DIRTY_OBSERVE, bitmap, sizeof(bitmap), &generation),
	    EPROTO);
	ATF_REQUIRE_EQ(migration_precopy_disable(owner), 0);
}

ATF_TC_WITHOUT_HEAD(default_adapter_rejects_ineligible_topology);
ATF_TC_BODY(default_adapter_rejects_ineligible_topology, tc)
{
	size_t bytes;

	(void)tc;
	migration_preflight_error = ENOTSUP;
	default_enabled = false;
	ATF_CHECK_EQ(migration_precopy_enable(owner, 0, 16 * 4096), ENOTSUP);
	ATF_CHECK(!default_enabled);
	ATF_CHECK_EQ(migration_dirty_bitmap_bytes(owner, &bytes), ENOENT);
	migration_preflight_error = 0;
}

/* ------------------------------------------------------------------------- */
/* Advisory free-page set + a simulated initial-copy walk.                   */
/* ------------------------------------------------------------------------- */

#define	FS_PAGES	16
#define	FS_GRAN		MIGRATION_DIRTY_GRANULARITY
#define	FS_SENTINEL	0xEEu

ATF_TC_WITHOUT_HEAD(free_set_marks_only_whole_covered_pages);
ATF_TC_BODY(free_set_marks_only_whole_covered_pages, tc)
{
	struct migration_precopy_free_set set;

	(void)tc;
	ATF_REQUIRE_EQ(migration_precopy_free_set_init(&set, 0,
	    FS_PAGES * FS_GRAN), 0);

	/* Nothing counts as free until the round is committed. */
	ATF_REQUIRE_EQ(migration_precopy_free_set_mark(&set, 3 * FS_GRAN,
	    2 * FS_GRAN), 0);
	ATF_CHECK(!migration_precopy_free_set_contains(&set, 3 * FS_GRAN));

	/* A sub-page fragment covers no whole page and marks nothing. */
	ATF_REQUIRE_EQ(migration_precopy_free_set_mark(&set, 7 * FS_GRAN + 100,
	    FS_GRAN), 0);
	/* An out-of-window range is clamped away. */
	ATF_REQUIRE_EQ(migration_precopy_free_set_mark(&set, 100 * FS_GRAN,
	    FS_GRAN), 0);

	migration_precopy_free_set_commit(&set);
	ATF_CHECK(migration_precopy_free_set_contains(&set, 3 * FS_GRAN));
	ATF_CHECK(migration_precopy_free_set_contains(&set, 4 * FS_GRAN));
	ATF_CHECK(!migration_precopy_free_set_contains(&set, 5 * FS_GRAN));
	/* The straddling fragment left pages 7 and 8 untouched. */
	ATF_CHECK(!migration_precopy_free_set_contains(&set, 7 * FS_GRAN));
	ATF_CHECK(!migration_precopy_free_set_contains(&set, 8 * FS_GRAN));
	/* Unaligned and out-of-range queries are never "free". */
	ATF_CHECK(!migration_precopy_free_set_contains(&set, 3 * FS_GRAN + 1));
	ATF_CHECK(!migration_precopy_free_set_contains(&set, 100 * FS_GRAN));

	/* The skip predicate honors the set only on the initial generation. */
	ATF_CHECK(migration_precopy_free_set_skip(&set, true, 3 * FS_GRAN));
	ATF_CHECK(!migration_precopy_free_set_skip(&set, false, 3 * FS_GRAN));
	ATF_CHECK(!migration_precopy_free_set_skip(&set, true, 5 * FS_GRAN));

	migration_precopy_free_set_reset(&set);
	/* A reset set is inert and never claims a page free. */
	ATF_CHECK(!migration_precopy_free_set_skip(&set, true, 3 * FS_GRAN));
}

ATF_TC_WITHOUT_HEAD(free_set_invalid_when_uncommitted);
ATF_TC_BODY(free_set_invalid_when_uncommitted, tc)
{
	struct migration_precopy_free_set set;

	(void)tc;
	/* Zeroed (never initialized) set: skip nothing. */
	memset(&set, 0, sizeof(set));
	ATF_CHECK(!migration_precopy_free_set_skip(&set, true, 0));

	/* Initialized but not committed (e.g. a failed/timed-out round). */
	ATF_REQUIRE_EQ(migration_precopy_free_set_init(&set, 0,
	    FS_PAGES * FS_GRAN), 0);
	ATF_REQUIRE_EQ(migration_precopy_free_set_mark(&set, 0, FS_GRAN), 0);
	ATF_CHECK(!migration_precopy_free_set_skip(&set, true, 0));
	migration_precopy_free_set_reset(&set);
}

/*
 * Mirror prod_precopy_round's per-page decision: emit a dirty page unless the
 * free set may suppress it on the initial generation.  Copies from source to
 * dest and clears the dirty bit, exactly as the real walk does.
 */
static void
run_walk(uint8_t *dest, const uint8_t *source, uint8_t *dirty,
    const struct migration_precopy_free_set *set, bool initial,
    unsigned int *copied, unsigned int *skipped_free)
{
	*copied = 0;
	*skipped_free = 0;
	for (unsigned int p = 0; p < FS_PAGES; p++) {
		if (dirty[p] == 0)
			continue;
		if (migration_precopy_free_set_skip(set, initial,
		    (uint64_t)p * FS_GRAN)) {
			(*skipped_free)++;
			continue;
		}
		dest[p] = source[p];
		dirty[p] = 0;
		(*copied)++;
	}
}

ATF_TC_WITHOUT_HEAD(initial_copy_skips_free_then_dirtied_is_copied);
ATF_TC_BODY(initial_copy_skips_free_then_dirtied_is_copied, tc)
{
	struct migration_precopy_free_set set;
	uint8_t source[FS_PAGES], dirty[FS_PAGES];
	uint8_t dest_full[FS_PAGES], dest_opt[FS_PAGES], dest_bug[FS_PAGES];
	unsigned int copied, skipped;
	const unsigned int free_pages[] = { 2, 5, 9 };
	const unsigned int dirtied = 5;	/* free, then written before cutover */

	(void)tc;
	for (unsigned int p = 0; p < FS_PAGES; p++)
		source[p] = (uint8_t)(0x40 + p);

	/* Reference: a full migration copies every page verbatim. */
	memset(dest_full, FS_SENTINEL, sizeof(dest_full));
	memset(dirty, 1, sizeof(dirty));
	memset(&set, 0, sizeof(set));	/* no free set: copy everything */
	run_walk(dest_full, source, dirty, &set, true, &copied, &skipped);
	ATF_CHECK_EQ(copied, FS_PAGES);
	ATF_CHECK_EQ(skipped, 0u);
	ATF_CHECK_EQ(memcmp(dest_full, source, FS_PAGES), 0);

	/* Build the committed free set {2, 5, 9}. */
	ATF_REQUIRE_EQ(migration_precopy_free_set_init(&set, 0,
	    FS_PAGES * FS_GRAN), 0);
	for (unsigned int i = 0; i < nitems(free_pages); i++)
		ATF_REQUIRE_EQ(migration_precopy_free_set_mark(&set,
		    (uint64_t)free_pages[i] * FS_GRAN, FS_GRAN), 0);
	migration_precopy_free_set_commit(&set);

	/* Optimized initial copy: the three free pages are skipped. */
	memset(dest_opt, FS_SENTINEL, sizeof(dest_opt));
	memset(dirty, 1, sizeof(dirty));
	run_walk(dest_opt, source, dirty, &set, true, &copied, &skipped);
	ATF_CHECK_EQ(skipped, nitems(free_pages));		/* (a) */
	ATF_CHECK_EQ(copied, FS_PAGES - nitems(free_pages));
	for (unsigned int p = 0; p < FS_PAGES; p++) {
		bool is_free = false;

		for (unsigned int i = 0; i < nitems(free_pages); i++)
			is_free |= free_pages[i] == p;
		if (is_free)
			ATF_CHECK_EQ(dest_opt[p], FS_SENTINEL);	/* (a) skipped */
		else
			ATF_CHECK_EQ(dest_opt[p], source[p]);	/* (d) copied */
	}

	/* The guest writes a page it had reported free, before cutover. */
	source[dirtied] = 0xA5;
	memset(dirty, 0, sizeof(dirty));
	dirty[dirtied] = 1;

	/* Later (non-initial) generation: the free set no longer applies. */
	run_walk(dest_opt, source, dirty, &set, false, &copied, &skipped);
	ATF_CHECK_EQ(copied, 1u);			/* (b) it is copied */
	ATF_CHECK_EQ(skipped, 0u);			/* (d) nothing skipped */
	ATF_CHECK_EQ(dest_opt[dirtied], source[dirtied]);

	/*
	 * Byte-identical to a full migration of the same final state: a full
	 * copy of the post-write source yields exactly dest_opt[dirtied].
	 */
	memset(dest_full, FS_SENTINEL, sizeof(dest_full));
	memset(dirty, 1, sizeof(dirty));
	{
		struct migration_precopy_free_set none;

		memset(&none, 0, sizeof(none));
		run_walk(dest_full, source, dirty, &none, true, &copied,
		    &skipped);
	}
	ATF_CHECK_EQ(dest_opt[dirtied], dest_full[dirtied]);

	/*
	 * Mutation check: a broken build that keeps consulting the free set on
	 * the later generation (initial=true) would skip the re-dirtied page and
	 * lose the write.  Prove the scenario is sensitive to that bug.
	 */
	memcpy(dest_bug, dest_opt, sizeof(dest_bug));
	dest_bug[dirtied] = FS_SENTINEL;	/* undo the correct copy */
	dirty[dirtied] = 1;
	run_walk(dest_bug, source, dirty, &set, true, &copied, &skipped);
	ATF_CHECK_EQ(copied, 0u);
	ATF_CHECK_EQ(skipped, 1u);
	ATF_CHECK(dest_bug[dirtied] != source[dirtied]);	/* data lost */

	migration_precopy_free_set_reset(&set);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, free_set_marks_only_whole_covered_pages);
	ATF_TP_ADD_TC(tp, free_set_invalid_when_uncommitted);
	ATF_TP_ADD_TC(tp, initial_copy_skips_free_then_dirtied_is_copied);
	ATF_TP_ADD_TC(tp, enable_rollback_is_fail_closed);
	ATF_TP_ADD_TC(tp, iterative_clear_keeps_device_dirties_cumulative);
	ATF_TP_ADD_TC(tp, cpu_failure_aborts_device_cut_atomically);
	ATF_TP_ADD_TC(tp, clear_failure_is_cleanup_only);
	ATF_TP_ADD_TC(tp, partial_disable_is_retryable_cleanup);
	ATF_TP_ADD_TC(tp, concurrent_lifecycle_is_serialized);
	ATF_TP_ADD_TC(tp, rejects_alias_and_invalid_cpu_metadata);
	ATF_TP_ADD_TC(tp, default_adapter_uses_self_describing_publication);
	ATF_TP_ADD_TC(tp, default_adapter_rejects_mismatched_publication);
	ATF_TP_ADD_TC(tp, default_adapter_rejects_ineligible_topology);
	return (atf_no_error());
}
