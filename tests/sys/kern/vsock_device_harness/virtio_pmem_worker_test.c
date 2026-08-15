/*
 * Event-driven worker and lifecycle tests for VirtIO PMEM flushes.
 */
#include <sys/param.h>
#include <sys/types.h>

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include <atf-c.h>

#include "virtio_pmem_async.c"
#include "virtio_pmem_worker.c"

struct worker_context {
	pthread_mutex_t mutex;
	pthread_cond_t condition;
	uintptr_t tokens[8];
	uint64_t epochs[8];
	int errors[8];
	size_t completed;
	unsigned int flushes;
	int flush_error;
	bool block;
	bool entered;
	bool release;
	bool block_complete;
	bool complete_entered;
	bool complete_release;
};

static int
test_flush(void *arg)
{
	struct worker_context *context;
	int error;

	context = arg;
	pthread_mutex_lock(&context->mutex);
	context->flushes++;
	context->entered = true;
	(void)pthread_cond_broadcast(&context->condition);
	while (context->block && !context->release)
		(void)pthread_cond_wait(&context->condition, &context->mutex);
	error = context->flush_error;
	pthread_mutex_unlock(&context->mutex);
	return (error);
}

static void
test_complete(void *arg, uintptr_t token, uint64_t epoch, int error)
{
	struct worker_context *context;
	size_t index;

	context = arg;
	pthread_mutex_lock(&context->mutex);
	context->complete_entered = true;
	(void)pthread_cond_broadcast(&context->condition);
	while (context->block_complete && !context->complete_release)
		(void)pthread_cond_wait(&context->condition, &context->mutex);
	index = context->completed++;
	if (index < nitems(context->tokens)) {
		context->tokens[index] = token;
		context->epochs[index] = epoch;
		context->errors[index] = error;
	}
	(void)pthread_cond_broadcast(&context->condition);
	pthread_mutex_unlock(&context->mutex);
}

static void
wait_for_completion_entry(struct worker_context *context)
{
	struct timespec deadline;
	int error;

	ATF_REQUIRE_EQ(clock_gettime(CLOCK_MONOTONIC, &deadline), 0);
	deadline.tv_sec++;
	pthread_mutex_lock(&context->mutex);
	while (!context->complete_entered) {
		error = pthread_cond_timedwait(&context->condition,
		    &context->mutex, &deadline);
		ATF_REQUIRE_MSG(error == 0,
		    "worker completion did not begin: %s", strerror(error));
	}
	pthread_mutex_unlock(&context->mutex);
}

static void
context_init(struct worker_context *context)
{
	pthread_condattr_t attr;

	memset(context, 0, sizeof(*context));
	ATF_REQUIRE_EQ(pthread_mutex_init(&context->mutex, NULL), 0);
	ATF_REQUIRE_EQ(pthread_condattr_init(&attr), 0);
	ATF_REQUIRE_EQ(pthread_condattr_setclock(&attr, CLOCK_MONOTONIC), 0);
	ATF_REQUIRE_EQ(pthread_cond_init(&context->condition, &attr), 0);
	ATF_REQUIRE_EQ(pthread_condattr_destroy(&attr), 0);
}

static void
context_fini(struct worker_context *context)
{

	ATF_REQUIRE_EQ(pthread_cond_destroy(&context->condition), 0);
	ATF_REQUIRE_EQ(pthread_mutex_destroy(&context->mutex), 0);
}

static void
wait_for_context(struct worker_context *context, size_t completed,
    bool entered)
{
	struct timespec deadline;
	int error;

	ATF_REQUIRE_EQ(clock_gettime(CLOCK_MONOTONIC, &deadline), 0);
	deadline.tv_sec++;
	pthread_mutex_lock(&context->mutex);
	while (context->completed < completed ||
	    (entered && !context->entered)) {
		error = pthread_cond_timedwait(&context->condition,
		    &context->mutex, &deadline);
		ATF_REQUIRE_MSG(error == 0, "worker did not make progress: %s",
		    strerror(error));
	}
	pthread_mutex_unlock(&context->mutex);
}

static struct virtio_pmem_worker *
create_worker(struct worker_context *context, size_t capacity)
{
	struct virtio_pmem_worker_ops ops;
	struct virtio_pmem_worker *worker;

	ops = (struct virtio_pmem_worker_ops) {
		.flush = test_flush,
		.complete = test_complete,
		.arg = context,
	};
	ATF_REQUIRE_EQ(virtio_pmem_worker_create(capacity, &ops, &worker), 0);
	return (worker);
}

ATF_TC_WITHOUT_HEAD(fifo_completion_precedes_pause);
ATF_TC_BODY(fifo_completion_precedes_pause, tc)
{
	struct virtio_pmem_worker *worker;
	struct worker_context context;
	uint64_t epoch;

	context_init(&context);
	worker = create_worker(&context, 4);
	ATF_REQUIRE_EQ(virtio_pmem_worker_submit(worker, 1, &epoch), 0);
	ATF_REQUIRE_EQ(virtio_pmem_worker_submit(worker, 2, &epoch), 0);
	ATF_REQUIRE_EQ(virtio_pmem_worker_submit(worker, 3, &epoch), 0);
	wait_for_context(&context, 3, false);
	ATF_CHECK_EQ(context.tokens[0], 1);
	ATF_CHECK_EQ(context.tokens[1], 2);
	ATF_CHECK_EQ(context.tokens[2], 3);
	ATF_CHECK_EQ(context.flushes, 3);
	ATF_REQUIRE_EQ(virtio_pmem_worker_pause(worker, 1000), 0);
	ATF_REQUIRE_EQ(virtio_pmem_worker_resume(worker), 0);
	ATF_REQUIRE_EQ(virtio_pmem_worker_destroy(worker, 1000), 0);
	context_fini(&context);
}

ATF_TC_WITHOUT_HEAD(blocked_flush_has_bounded_pause);
ATF_TC_BODY(blocked_flush_has_bounded_pause, tc)
{
	struct virtio_pmem_worker *worker;
	struct worker_context context;
	uint64_t epoch;
	size_t pending;
	bool accepting;

	context_init(&context);
	context.block = true;
	worker = create_worker(&context, 2);
	ATF_REQUIRE_EQ(virtio_pmem_worker_submit(worker, 10, &epoch), 0);
	wait_for_context(&context, 0, true);
	ATF_CHECK_EQ(virtio_pmem_worker_pause(worker, 1), ETIMEDOUT);
	ATF_REQUIRE_EQ(virtio_pmem_worker_pending(worker, &pending,
	    &accepting), 0);
	ATF_CHECK_EQ(pending, 1);
	ATF_CHECK(!accepting);
	ATF_REQUIRE_EQ(virtio_pmem_worker_abort_pause(worker), 0);
	ATF_REQUIRE_EQ(virtio_pmem_worker_pending(worker, &pending,
	    &accepting), 0);
	ATF_CHECK(accepting);
	pthread_mutex_lock(&context.mutex);
	context.release = true;
	(void)pthread_cond_broadcast(&context.condition);
	pthread_mutex_unlock(&context.mutex);
	wait_for_context(&context, 1, false);
	ATF_REQUIRE_EQ(virtio_pmem_worker_pause(worker, 1000), 0);
	ATF_REQUIRE_EQ(virtio_pmem_worker_destroy(worker, 1000), 0);
	context_fini(&context);
}

ATF_TC_WITHOUT_HEAD(reset_preserves_suspend_and_epoch);
ATF_TC_BODY(reset_preserves_suspend_and_epoch, tc)
{
	struct virtio_pmem_worker *worker;
	struct worker_context context;
	uint64_t first_epoch, second_epoch;

	context_init(&context);
	worker = create_worker(&context, 2);
	ATF_REQUIRE_EQ(virtio_pmem_worker_submit(worker, 20, &first_epoch), 0);
	wait_for_context(&context, 1, false);
	ATF_REQUIRE_EQ(virtio_pmem_worker_reset(worker, 1000, false), 0);
	ATF_CHECK_EQ(virtio_pmem_worker_submit(worker, 20, &second_epoch),
	    EBUSY);
	ATF_REQUIRE_EQ(virtio_pmem_worker_resume(worker), 0);
	ATF_REQUIRE_EQ(virtio_pmem_worker_submit(worker, 20, &second_epoch), 0);
	ATF_CHECK(first_epoch != second_epoch);
	wait_for_context(&context, 2, false);
	ATF_REQUIRE_EQ(virtio_pmem_worker_destroy(worker, 1000), 0);
	context_fini(&context);
}

ATF_TC_WITHOUT_HEAD(blocked_completion_remains_owned);
ATF_TC_BODY(blocked_completion_remains_owned, tc)
{
	struct virtio_pmem_worker *worker;
	struct worker_context context;
	uint64_t epoch;
	size_t pending;
	bool accepting;

	context_init(&context);
	context.block_complete = true;
	worker = create_worker(&context, 1);
	ATF_REQUIRE_EQ(virtio_pmem_worker_submit(worker, 25, &epoch), 0);
	wait_for_completion_entry(&context);
	ATF_CHECK_EQ(virtio_pmem_worker_pause(worker, 1), ETIMEDOUT);
	ATF_REQUIRE_EQ(virtio_pmem_worker_pending(worker, &pending,
	    &accepting), 0);
	ATF_CHECK_EQ(pending, 1);
	ATF_CHECK(!accepting);
	pthread_mutex_lock(&context.mutex);
	context.complete_release = true;
	(void)pthread_cond_broadcast(&context.condition);
	pthread_mutex_unlock(&context.mutex);
	wait_for_context(&context, 1, false);
	ATF_REQUIRE_EQ(virtio_pmem_worker_pause(worker, 1000), 0);
	ATF_REQUIRE_EQ(virtio_pmem_worker_destroy(worker, 1000), 0);
	context_fini(&context);
}

ATF_TC_WITHOUT_HEAD(timed_out_reset_defers_reopen_until_completion);
ATF_TC_BODY(timed_out_reset_defers_reopen_until_completion, tc)
{
	struct virtio_pmem_worker *worker;
	struct worker_context context;
	struct timespec deadline;
	uint64_t first_epoch, second_epoch;
	size_t pending;
	bool accepting;
	int error;

	context_init(&context);
	context.block_complete = true;
	worker = create_worker(&context, 1);
	ATF_REQUIRE_EQ(virtio_pmem_worker_submit(worker, 26, &first_epoch), 0);
	wait_for_completion_entry(&context);
	ATF_REQUIRE_EQ(virtio_pmem_worker_reset(worker, 1, true), ETIMEDOUT);
	ATF_REQUIRE_EQ(virtio_pmem_worker_defer_reset(worker, true), 0);
	/* A checkpoint rollback cannot steal a pending full-reset owner. */
	ATF_CHECK_EQ(virtio_pmem_worker_abort_pause(worker), EBUSY);
	ATF_CHECK_EQ(virtio_pmem_worker_submit(worker, 27, &second_epoch), EBUSY);
	pthread_mutex_lock(&context.mutex);
	context.complete_release = true;
	(void)pthread_cond_broadcast(&context.condition);
	pthread_mutex_unlock(&context.mutex);

	ATF_REQUIRE_EQ(clock_gettime(CLOCK_MONOTONIC, &deadline), 0);
	deadline.tv_sec++;
	pthread_mutex_lock(&worker->mutex);
	for (;;) {
		ATF_REQUIRE_EQ(virtio_pmem_worker_pending(worker, &pending,
		    &accepting), 0);
		if (pending == 0 && accepting)
			break;
		error = pthread_cond_timedwait(&worker->condition,
		    &worker->mutex, &deadline);
		ATF_REQUIRE_MSG(error == 0,
		    "deferred reset did not reopen: %s", strerror(error));
	}
	pthread_mutex_unlock(&worker->mutex);
	ATF_REQUIRE_EQ(virtio_pmem_worker_submit(worker, 27, &second_epoch), 0);
	ATF_CHECK(first_epoch != second_epoch);
	wait_for_context(&context, 2, false);
	ATF_REQUIRE_EQ(virtio_pmem_worker_destroy(worker, 1000), 0);
	context_fini(&context);
}

ATF_TC_WITHOUT_HEAD(flush_error_is_published_once);
ATF_TC_BODY(flush_error_is_published_once, tc)
{
	struct virtio_pmem_worker *worker;
	struct worker_context context;
	uint64_t epoch;

	context_init(&context);
	context.flush_error = EIO;
	worker = create_worker(&context, 1);
	ATF_REQUIRE_EQ(virtio_pmem_worker_submit(worker, 30, &epoch), 0);
	wait_for_context(&context, 1, false);
	ATF_CHECK_EQ(context.completed, 1);
	ATF_CHECK_EQ(context.errors[0], EIO);
	ATF_REQUIRE_EQ(virtio_pmem_worker_destroy(worker, 1000), 0);
	context_fini(&context);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, fifo_completion_precedes_pause);
	ATF_TP_ADD_TC(tp, blocked_flush_has_bounded_pause);
	ATF_TP_ADD_TC(tp, reset_preserves_suspend_and_epoch);
	ATF_TP_ADD_TC(tp, blocked_completion_remains_owned);
	ATF_TP_ADD_TC(tp, timed_out_reset_defers_reopen_until_completion);
	ATF_TP_ADD_TC(tp, flush_error_is_published_once);
	return (atf_no_error());
}
