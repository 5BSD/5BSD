/*
 * Bounded lifecycle tests for the asynchronous VirtIO PMEM owner ledger.
 */
#include <sys/param.h>
#include <sys/types.h>

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

#include <atf-c.h>

#include "virtio_pmem_async.c"

#define	PMEM_ASYNC_PRODUCERS	4U
#define	PMEM_ASYNC_PER_PRODUCER	16U

struct producer_context {
	struct virtio_pmem_async *async;
	pthread_barrier_t *barrier;
	unsigned int producer;
	int errors[PMEM_ASYNC_PER_PRODUCER];
};

static void *
submit_producer(void *arg)
{
	struct producer_context *context;
	uint64_t epoch;
	uintptr_t token;

	context = arg;
	(void)pthread_barrier_wait(context->barrier);
	for (unsigned int i = 0; i < PMEM_ASYNC_PER_PRODUCER; i++) {
		token = 1 + context->producer * PMEM_ASYNC_PER_PRODUCER + i;
		context->errors[i] = virtio_pmem_async_submit(context->async,
		    token, &epoch);
	}
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(fifo_and_capacity);
ATF_TC_BODY(fifo_and_capacity, tc)
{
	struct virtio_pmem_async_job job;
	struct virtio_pmem_async *async;
	uint64_t epoch[3];

	ATF_REQUIRE_EQ(virtio_pmem_async_create(2, &async), 0);
	ATF_REQUIRE_EQ(virtio_pmem_async_submit(async, 11, &epoch[0]), 0);
	ATF_REQUIRE_EQ(virtio_pmem_async_submit(async, 12, &epoch[1]), 0);
	ATF_CHECK_EQ(epoch[0], epoch[1]);
	ATF_CHECK_EQ(virtio_pmem_async_submit(async, 13, &epoch[2]), ENOSPC);
	ATF_REQUIRE_EQ(virtio_pmem_async_acquire(async, &job), 0);
	ATF_CHECK_EQ(job.token, 11);
	ATF_CHECK_EQ(virtio_pmem_async_acquire(async, &job), EBUSY);
	/* The active owner counts against the configured ownership bound. */
	ATF_CHECK_EQ(virtio_pmem_async_submit(async, 13, &epoch[2]), ENOSPC);
	ATF_REQUIRE_EQ(virtio_pmem_async_complete(async, &job), 0);
	ATF_REQUIRE_EQ(virtio_pmem_async_submit(async, 13, &epoch[2]), 0);
	ATF_REQUIRE_EQ(virtio_pmem_async_acquire(async, &job), 0);
	ATF_CHECK_EQ(job.token, 12);
	ATF_REQUIRE_EQ(virtio_pmem_async_complete(async, &job), 0);
	ATF_REQUIRE_EQ(virtio_pmem_async_acquire(async, &job), 0);
	ATF_CHECK_EQ(job.token, 13);
	ATF_REQUIRE_EQ(virtio_pmem_async_complete(async, &job), 0);
	ATF_CHECK_EQ(virtio_pmem_async_acquire(async, &job), EAGAIN);
	ATF_REQUIRE_EQ(virtio_pmem_async_destroy(async), 0);
}

ATF_TC_WITHOUT_HEAD(pause_drains_without_polling);
ATF_TC_BODY(pause_drains_without_polling, tc)
{
	struct virtio_pmem_async_job job;
	struct virtio_pmem_async *async;
	uint64_t epoch;
	size_t pending;
	bool accepting;

	ATF_REQUIRE_EQ(virtio_pmem_async_create(3, &async), 0);
	ATF_REQUIRE_EQ(virtio_pmem_async_submit(async, 21, &epoch), 0);
	ATF_REQUIRE_EQ(virtio_pmem_async_submit(async, 22, &epoch), 0);
	ATF_CHECK_EQ(virtio_pmem_async_pause(async, &pending), EINPROGRESS);
	ATF_CHECK_EQ(pending, 2);
	ATF_CHECK_EQ(virtio_pmem_async_submit(async, 23, &epoch), EBUSY);
	ATF_CHECK_EQ(virtio_pmem_async_resume(async), EBUSY);
	ATF_REQUIRE_EQ(virtio_pmem_async_abort_pause(async), 0);
	ATF_REQUIRE_EQ(virtio_pmem_async_pending(async, &pending,
	    &accepting), 0);
	ATF_CHECK(accepting);
	ATF_REQUIRE_EQ(virtio_pmem_async_pause(async, &pending), EINPROGRESS);

	ATF_REQUIRE_EQ(virtio_pmem_async_acquire(async, &job), 0);
	ATF_REQUIRE_EQ(virtio_pmem_async_complete(async, &job), 0);
	ATF_REQUIRE_EQ(virtio_pmem_async_acquire(async, &job), 0);
	ATF_REQUIRE_EQ(virtio_pmem_async_complete(async, &job), 0);
	ATF_REQUIRE_EQ(virtio_pmem_async_pending(async, &pending,
	    &accepting), 0);
	ATF_CHECK_EQ(pending, 0);
	ATF_CHECK(!accepting);
	ATF_REQUIRE_EQ(virtio_pmem_async_resume(async), 0);
	ATF_REQUIRE_EQ(virtio_pmem_async_pending(async, &pending,
	    &accepting), 0);
	ATF_CHECK(accepting);
	ATF_REQUIRE_EQ(virtio_pmem_async_destroy(async), 0);
}

ATF_TC_WITHOUT_HEAD(reset_epoch_and_stale_completion);
ATF_TC_BODY(reset_epoch_and_stale_completion, tc)
{
	struct virtio_pmem_async_job current, job, stale;
	struct virtio_pmem_async *async;
	uint64_t first_epoch, second_epoch;
	size_t pending;

	ATF_REQUIRE_EQ(virtio_pmem_async_create(2, &async), 0);
	ATF_REQUIRE_EQ(virtio_pmem_async_submit(async, 31, &first_epoch), 0);
	ATF_REQUIRE_EQ(virtio_pmem_async_acquire(async, &job), 0);
	current = job;
	current.token++;
	ATF_CHECK_EQ(virtio_pmem_async_complete(async, &current), ESTALE);
	ATF_CHECK_EQ(virtio_pmem_async_finish_reset(async, true), EBUSY);
	ATF_CHECK_EQ(virtio_pmem_async_pause(async, &pending), EINPROGRESS);
	ATF_CHECK_EQ(pending, 1);
	stale = job;
	ATF_REQUIRE_EQ(virtio_pmem_async_complete(async, &job), 0);
	/* A reset completed under suspension must not reopen admission. */
	ATF_REQUIRE_EQ(virtio_pmem_async_finish_reset(async, false), 0);
	ATF_CHECK_EQ(virtio_pmem_async_submit(async, 31, &second_epoch), EBUSY);
	ATF_REQUIRE_EQ(virtio_pmem_async_resume(async), 0);
	ATF_REQUIRE_EQ(virtio_pmem_async_submit(async, 31, &second_epoch), 0);
	ATF_CHECK(first_epoch != second_epoch);
	ATF_REQUIRE_EQ(virtio_pmem_async_acquire(async, &current), 0);
	ATF_CHECK_EQ(virtio_pmem_async_complete(async, &stale), ESTALE);
	ATF_REQUIRE_EQ(virtio_pmem_async_complete(async, &current), 0);
	ATF_REQUIRE_EQ(virtio_pmem_async_destroy(async), 0);
}

ATF_TC_WITHOUT_HEAD(deferred_reset_reopens_after_last_owner);
ATF_TC_BODY(deferred_reset_reopens_after_last_owner, tc)
{
	struct virtio_pmem_async_job job;
	struct virtio_pmem_async *async;
	uint64_t first_epoch, second_epoch;
	size_t pending;
	bool accepting;

	ATF_REQUIRE_EQ(virtio_pmem_async_create(2, &async), 0);
	/* No old owner survives reset, so epoch rollover is ABA-safe. */
	async->epoch = UINT64_MAX;
	ATF_REQUIRE_EQ(virtio_pmem_async_submit(async, 35, &first_epoch), 0);
	ATF_CHECK_EQ(first_epoch, UINT64_MAX);
	ATF_REQUIRE_EQ(virtio_pmem_async_acquire(async, &job), 0);
	ATF_REQUIRE_EQ(virtio_pmem_async_pause(async, &pending), EINPROGRESS);
	ATF_REQUIRE_EQ(virtio_pmem_async_defer_reset(async, true), 0);
	ATF_CHECK_EQ(virtio_pmem_async_abort_pause(async), EBUSY);
	ATF_CHECK_EQ(virtio_pmem_async_submit(async, 36, &second_epoch), EBUSY);
	ATF_REQUIRE_EQ(virtio_pmem_async_complete(async, &job), 0);
	ATF_REQUIRE_EQ(virtio_pmem_async_pending(async, &pending,
	    &accepting), 0);
	ATF_CHECK_EQ(pending, 0);
	ATF_CHECK(accepting);
	ATF_REQUIRE_EQ(virtio_pmem_async_submit(async, 36, &second_epoch), 0);
	ATF_CHECK_EQ(second_epoch, 1);
	ATF_REQUIRE_EQ(virtio_pmem_async_acquire(async, &job), 0);
	ATF_REQUIRE_EQ(virtio_pmem_async_complete(async, &job), 0);
	ATF_REQUIRE_EQ(virtio_pmem_async_destroy(async), 0);
}

ATF_TC_WITHOUT_HEAD(validation_and_busy_destroy);
ATF_TC_BODY(validation_and_busy_destroy, tc)
{
	struct virtio_pmem_async *async = NULL;
	uint64_t epoch;

	ATF_CHECK_EQ(virtio_pmem_async_create(0, &async), EINVAL);
	ATF_CHECK_EQ(virtio_pmem_async_create(
	    BHYVE_VIRTIO_PMEM_ASYNC_MAX + 1, &async), EINVAL);
	ATF_REQUIRE_EQ(virtio_pmem_async_create(1, &async), 0);
	ATF_CHECK_EQ(virtio_pmem_async_submit(async, 0, &epoch), EINVAL);
	ATF_REQUIRE_EQ(virtio_pmem_async_submit(async, 41, &epoch), 0);
	ATF_CHECK_EQ(virtio_pmem_async_destroy(async), EBUSY);
	ATF_CHECK_EQ(virtio_pmem_async_submit(async, 41, &epoch), EEXIST);
	ATF_REQUIRE_EQ(virtio_pmem_async_pause(async, &(size_t){ 0 }),
	    EINPROGRESS);
	/* The owner remains deliberately live; drain it before destruction. */
	struct virtio_pmem_async_job job;
	ATF_REQUIRE_EQ(virtio_pmem_async_acquire(async, &job), 0);
	ATF_REQUIRE_EQ(virtio_pmem_async_complete(async, &job), 0);
	ATF_REQUIRE_EQ(virtio_pmem_async_destroy(async), 0);
}

ATF_TC_WITHOUT_HEAD(concurrent_admission_is_bounded);
ATF_TC_BODY(concurrent_admission_is_bounded, tc)
{
	struct producer_context context[PMEM_ASYNC_PRODUCERS];
	struct virtio_pmem_async_job job;
	struct virtio_pmem_async *async;
	pthread_barrier_t barrier;
	pthread_t threads[PMEM_ASYNC_PRODUCERS];
	bool seen[PMEM_ASYNC_PRODUCERS * PMEM_ASYNC_PER_PRODUCER] = { false };
	bool accepting;
	size_t pending;

	ATF_REQUIRE_EQ(virtio_pmem_async_create(nitems(seen), &async), 0);
	ATF_REQUIRE_EQ(pthread_barrier_init(&barrier, NULL,
	    PMEM_ASYNC_PRODUCERS + 1), 0);
	for (unsigned int i = 0; i < PMEM_ASYNC_PRODUCERS; i++) {
		context[i] = (struct producer_context) {
			.async = async,
			.barrier = &barrier,
			.producer = i,
		};
		ATF_REQUIRE_EQ(pthread_create(&threads[i], NULL,
		    submit_producer, &context[i]), 0);
	}
	(void)pthread_barrier_wait(&barrier);
	for (unsigned int i = 0; i < PMEM_ASYNC_PRODUCERS; i++) {
		ATF_REQUIRE_EQ(pthread_join(threads[i], NULL), 0);
		for (unsigned int j = 0; j < PMEM_ASYNC_PER_PRODUCER; j++)
			ATF_CHECK_EQ(context[i].errors[j], 0);
	}
	ATF_REQUIRE_EQ(virtio_pmem_async_pending(async, &pending,
	    &accepting), 0);
	ATF_CHECK_EQ(pending, nitems(seen));
	ATF_CHECK(accepting);
	for (size_t i = 0; i < nitems(seen); i++) {
		ATF_REQUIRE_EQ(virtio_pmem_async_acquire(async, &job), 0);
		ATF_REQUIRE(job.token >= 1 && job.token <= nitems(seen));
		ATF_CHECK(!seen[job.token - 1]);
		seen[job.token - 1] = true;
		ATF_REQUIRE_EQ(virtio_pmem_async_complete(async, &job), 0);
	}
	for (size_t i = 0; i < nitems(seen); i++)
		ATF_CHECK(seen[i]);
	ATF_REQUIRE_EQ(pthread_barrier_destroy(&barrier), 0);
	ATF_REQUIRE_EQ(virtio_pmem_async_destroy(async), 0);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, fifo_and_capacity);
	ATF_TP_ADD_TC(tp, pause_drains_without_polling);
	ATF_TP_ADD_TC(tp, reset_epoch_and_stale_completion);
	ATF_TP_ADD_TC(tp, deferred_reset_reopens_after_last_owner);
	ATF_TP_ADD_TC(tp, validation_and_busy_destroy);
	ATF_TP_ADD_TC(tp, concurrent_admission_is_bounded);
	return (atf_no_error());
}
