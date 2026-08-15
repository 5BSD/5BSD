/*
 * Bounded request-ownership tests for the VirtIO filesystem backend.
 */
#include <sys/types.h>

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include "virtio_fs_pending.c"

static struct virtio_fs_request_context
request_context(uint64_t unique, uint64_t incarnation)
{

	return ((struct virtio_fs_request_context) {
		.byte_order = VIRTIO_FS_BYTE_ORDER_LITTLE,
		.opcode = 1,
		.unique = unique,
		.incarnation = incarnation,
		.expects_reply = true,
	});
}

ATF_TC_WITHOUT_HEAD(bounds_duplicates_and_generations);
ATF_TC_BODY(bounds_duplicates_and_generations, tc)
{
	struct virtio_fs_request_context request;
	struct virtio_fs_pending_result result;
	struct virtio_fs_pending *pending;

	ATF_CHECK_EQ(virtio_fs_pending_create(0, 4096, &pending), EINVAL);
	ATF_CHECK_EQ(virtio_fs_pending_create(
	    VIRTIO_FS_BACKEND_MAX_INFLIGHT + 1U, 4096, &pending), EINVAL);
	ATF_CHECK_EQ(virtio_fs_pending_create(2, 0, &pending), EINVAL);
	/*
	 * The implementation rounds its request-id hash table up to twice the
	 * capacity.  Exercise the documented ceiling itself, not just the first
	 * rejected value, so this remains a checked 32-bit arithmetic boundary.
	 */
	ATF_REQUIRE_EQ(virtio_fs_pending_create(
	    VIRTIO_FS_BACKEND_MAX_INFLIGHT,
	    VIRTIO_FS_BACKEND_MAX_PENDING_BYTES, &pending), 0);
	virtio_fs_pending_destroy(pending);
	ATF_REQUIRE_EQ(virtio_fs_pending_create(2, 4096, &pending), 0);
	request = request_context(101, 3);
	ATF_CHECK_EQ(virtio_fs_pending_insert_owned(pending, 1, 7, &request,
	    1024, (uintptr_t)0x1234), 0);
	request.unique = 102;
	ATF_CHECK_EQ(virtio_fs_pending_insert(pending, 1, 7, &request, 1024),
	    EEXIST);
	ATF_CHECK_EQ(virtio_fs_pending_insert(pending, 2, 7, &request, 3072),
	    0);
	ATF_CHECK_EQ(virtio_fs_pending_bytes(pending), 4096);
	request.unique = 103;
	ATF_CHECK_EQ(virtio_fs_pending_insert(pending, 3, 7, &request, 1),
	    ENOSPC);
	ATF_CHECK_EQ(virtio_fs_pending_count(pending), 2);
	ATF_CHECK_EQ(virtio_fs_pending_remove(pending, 1, 8, &result),
	    ESTALE);
	ATF_REQUIRE_EQ(virtio_fs_pending_remove(pending, 1, 7, &result), 0);
	ATF_CHECK_EQ(result.request.unique, 101);
	ATF_CHECK_EQ(result.request.incarnation, 3);
	ATF_CHECK_EQ(result.owner_cookie, (uintptr_t)0x1234);
	ATF_CHECK_EQ(result.payload_len, 1024);
	ATF_CHECK(!result.cancel_requested);
	ATF_CHECK_EQ(virtio_fs_pending_bytes(pending), 3072);
	ATF_CHECK_EQ(virtio_fs_pending_insert(pending, 3, 8, &request, 1025),
	    ENOBUFS);
	ATF_CHECK_EQ(virtio_fs_pending_insert(pending, 3, 8, &request, 1024),
	    0);
	virtio_fs_pending_destroy(pending);
}

ATF_TC_WITHOUT_HEAD(cancel_and_atomic_drain);
ATF_TC_BODY(cancel_and_atomic_drain, tc)
{
	struct virtio_fs_request_context request;
	struct virtio_fs_pending_result results[3];
	struct virtio_fs_pending *pending;
	unsigned int cancelled;
	size_t count;

	ATF_REQUIRE_EQ(virtio_fs_pending_create(3, 4096, &pending), 0);
	for (uint64_t i = 1; i <= 3; i++) {
		request = request_context(100 + i, 2);
		ATF_REQUIRE_EQ(virtio_fs_pending_insert(pending, i, 9,
		    &request, 512), 0);
	}
	ATF_CHECK_EQ(virtio_fs_pending_cancel(pending, 2, 8), ESTALE);
	ATF_CHECK_EQ(virtio_fs_pending_cancel(pending, 2, 9), 0);
	ATF_CHECK_EQ(virtio_fs_pending_cancel(pending, 2, 9), EALREADY);
	ATF_CHECK_EQ(virtio_fs_pending_cancel(pending, 4, 9), ENOENT);
	count = 99;
	ATF_CHECK_EQ(virtio_fs_pending_drain(pending, results, 2, &count),
	    EMSGSIZE);
	ATF_CHECK_EQ(count, 3);
	ATF_CHECK_EQ(virtio_fs_pending_count(pending), 3);
	ATF_REQUIRE_EQ(virtio_fs_pending_drain(pending, results, 3,
	    &count), 0);
	ATF_CHECK_EQ(count, 3);
	ATF_CHECK_EQ(virtio_fs_pending_count(pending), 0);
	ATF_CHECK_EQ(virtio_fs_pending_bytes(pending), 0);
	cancelled = 0;
	for (size_t i = 0; i < count; i++) {
		if (results[i].cancel_requested) {
			cancelled++;
			ATF_CHECK_EQ(results[i].request_id, 2);
		}
	}
	ATF_CHECK_EQ(cancelled, 1);
	request = request_context(104, 3);
	ATF_CHECK_EQ(virtio_fs_pending_insert(pending, 4, 10, &request, 4096),
	    0);
	virtio_fs_pending_destroy(pending);
}

struct thread_context {
	struct virtio_fs_pending *pending;
	uint64_t base;
	unsigned int failures;
};

static void *
exercise_pending(void *argument)
{
	struct virtio_fs_pending_result result;
	struct virtio_fs_request_context request;
	struct thread_context *context;
	uint64_t id;

	context = argument;
	for (uint64_t i = 0; i < 1000; i++) {
		id = context->base + i;
		request = request_context(id + 1, 2);
		if (virtio_fs_pending_insert(context->pending, id, 4, &request,
		    64) !=
		    0 ||
		    virtio_fs_pending_remove(context->pending, id, 4, &result) !=
		    0 ||
		    result.request.unique != id + 1)
			context->failures++;
	}
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(concurrent_ownership);
ATF_TC_BODY(concurrent_ownership, tc)
{
	struct thread_context contexts[8];
	struct virtio_fs_pending *pending;
	pthread_t threads[8];

	ATF_REQUIRE_EQ(virtio_fs_pending_create(64, 4096, &pending), 0);
	memset(contexts, 0, sizeof(contexts));
	for (size_t i = 0; i < nitems(threads); i++) {
		contexts[i].pending = pending;
		contexts[i].base = UINT64_C(1) + i * UINT64_C(10000);
		ATF_REQUIRE_EQ(pthread_create(&threads[i], NULL,
		    exercise_pending, &contexts[i]), 0);
	}
	for (size_t i = 0; i < nitems(threads); i++) {
		ATF_REQUIRE_EQ(pthread_join(threads[i], NULL), 0);
		ATF_CHECK_EQ(contexts[i].failures, 0);
	}
	ATF_CHECK_EQ(virtio_fs_pending_count(pending), 0);
	virtio_fs_pending_destroy(pending);
}

ATF_TC_WITHOUT_HEAD(selective_queue_drain_is_atomic);
ATF_TC_BODY(selective_queue_drain_is_atomic, tc)
{
	struct virtio_fs_request_context request;
	struct virtio_fs_pending_result results[3], lookup;
	struct virtio_fs_pending *pending;
	size_t count;

	ATF_REQUIRE_EQ(virtio_fs_pending_create(4, 4096, &pending), 0);
	for (uint64_t i = 1; i <= 4; i++) {
		request = request_context(200 + i, 4);
		ATF_REQUIRE_EQ(virtio_fs_pending_insert_owned_on(pending, i, 11,
		    &request, 256, (uintptr_t)(0x100 + i),
		    i == 2 ? 7 : 9), 0);
	}
	ATF_REQUIRE_EQ(virtio_fs_pending_mark_sent(pending, 2, 11), 0);
	ATF_CHECK_EQ(virtio_fs_pending_mark_sent(pending, 2, 11), EALREADY);
	ATF_CHECK_EQ(virtio_fs_pending_drain_queue(pending, 7, results, 3,
	    &count), EBUSY);
	ATF_CHECK_EQ(count, 1);
	ATF_CHECK_EQ(virtio_fs_pending_count(pending), 4);
	count = 0;
	ATF_CHECK_EQ(virtio_fs_pending_drain_queue(pending, 9, results, 2,
	    &count), EMSGSIZE);
	ATF_CHECK_EQ(count, 3);
	ATF_CHECK_EQ(virtio_fs_pending_count(pending), 4);
	ATF_REQUIRE_EQ(virtio_fs_pending_drain_queue(pending, 9, results, 3,
	    &count), 0);
	ATF_CHECK_EQ(count, 3);
	ATF_CHECK_EQ(virtio_fs_pending_count(pending), 1);
	ATF_CHECK_EQ(virtio_fs_pending_bytes(pending), 256);
	for (size_t i = 0; i < count; i++) {
		ATF_CHECK_EQ(results[i].queue_id, 9);
		ATF_CHECK(results[i].request_id != 2);
	}
	ATF_REQUIRE_EQ(virtio_fs_pending_lookup(pending, 2, 11, &lookup), 0);
	ATF_CHECK_EQ(lookup.queue_id, 7);
	ATF_CHECK_EQ(lookup.owner_cookie, (uintptr_t)0x102);
	ATF_CHECK(lookup.sent);
	ATF_CHECK_EQ(virtio_fs_pending_drain_queue(pending, 9, results, 3,
	    &count), 0);
	ATF_CHECK_EQ(count, 0);
	virtio_fs_pending_destroy(pending);
}

ATF_TC_WITHOUT_HEAD(drain_publication_aliases_are_rejected);
ATF_TC_BODY(drain_publication_aliases_are_rejected, tc)
{
	struct virtio_fs_request_context request;
	struct virtio_fs_pending_result result;
	struct virtio_fs_pending *pending;
	size_t count;

	ATF_REQUIRE_EQ(virtio_fs_pending_create(2, 4096, &pending), 0);
	request = request_context(301, 5);
	ATF_REQUIRE_EQ(virtio_fs_pending_insert_owned_on(pending, 1, 12,
	    &request, 256, (uintptr_t)0x301, 9), 0);

	count = 77;
	ATF_CHECK_EQ(virtio_fs_pending_drain(pending,
	    (struct virtio_fs_pending_result *)(void *)pending, 1, &count),
	    EINVAL);
	ATF_CHECK_EQ(count, 77);
	ATF_CHECK_EQ(virtio_fs_pending_count(pending), 1);
	ATF_CHECK_EQ(virtio_fs_pending_drain(pending, &result, 1,
	    (size_t *)(void *)pending->entries), EINVAL);
	ATF_CHECK_EQ(virtio_fs_pending_count(pending), 1);
	ATF_CHECK_EQ(virtio_fs_pending_drain(pending,
	    (struct virtio_fs_pending_result *)(void *)&count, 1, &count),
	    EINVAL);
	ATF_CHECK_EQ(count, 77);
	ATF_CHECK_EQ(virtio_fs_pending_count(pending), 1);

	ATF_CHECK_EQ(virtio_fs_pending_drain_queue(pending, 9,
	    (struct virtio_fs_pending_result *)(void *)pending->buckets, 1,
	    &count), EINVAL);
	ATF_CHECK_EQ(count, 77);
	ATF_CHECK_EQ(virtio_fs_pending_count(pending), 1);
	ATF_CHECK_EQ(virtio_fs_pending_drain_queue(pending, 9, &result, 1,
	    (size_t *)(void *)pending), EINVAL);
	ATF_CHECK_EQ(virtio_fs_pending_count(pending), 1);

	ATF_REQUIRE_EQ(virtio_fs_pending_drain_queue(pending, 9, &result, 1,
	    &count), 0);
	ATF_CHECK_EQ(count, 1);
	ATF_CHECK_EQ(result.request_id, 1);
	ATF_CHECK_EQ(result.owner_cookie, (uintptr_t)0x301);
	ATF_CHECK_EQ(virtio_fs_pending_count(pending), 0);
	virtio_fs_pending_destroy(pending);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, bounds_duplicates_and_generations);
	ATF_TP_ADD_TC(tp, cancel_and_atomic_drain);
	ATF_TP_ADD_TC(tp, concurrent_ownership);
	ATF_TP_ADD_TC(tp, selective_queue_drain_is_atomic);
	ATF_TP_ADD_TC(tp, drain_publication_aliases_are_rejected);
	return (atf_no_error());
}
