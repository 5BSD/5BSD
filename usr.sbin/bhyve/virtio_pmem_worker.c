/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/errno.h>

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#include "virtio_pmem_async.h"
#include "virtio_pmem_worker.h"

struct virtio_pmem_worker {
	pthread_mutex_t mutex;
	pthread_cond_t condition;
	pthread_t thread;
	struct virtio_pmem_async *async;
	struct virtio_pmem_worker_ops ops;
	bool exiting;
};

static int
virtio_pmem_worker_deadline(uint32_t timeout_ms, struct timespec *deadline)
{
	uint64_t nanoseconds;

	if (deadline == NULL)
		return (EINVAL);
	if (clock_gettime(CLOCK_MONOTONIC, deadline) == -1)
		return (errno);
	nanoseconds = (uint64_t)deadline->tv_nsec +
	    (uint64_t)(timeout_ms % 1000) * UINT64_C(1000000);
	deadline->tv_sec += timeout_ms / 1000 + nanoseconds / UINT64_C(1000000000);
	deadline->tv_nsec = (long)(nanoseconds % UINT64_C(1000000000));
	return (0);
}

static void *
virtio_pmem_worker_main(void *arg)
{
	struct virtio_pmem_async_job job;
	struct virtio_pmem_worker *worker;
	int error, owner_error;

	worker = arg;
	pthread_mutex_lock(&worker->mutex);
	for (;;) {
		if (worker->exiting)
			break;
		error = virtio_pmem_async_acquire(worker->async, &job);
		if (error == EAGAIN) {
			(void)pthread_cond_wait(&worker->condition, &worker->mutex);
			continue;
		}
		if (error != 0) {
			(void)pthread_cond_wait(&worker->condition, &worker->mutex);
			continue;
		}

		pthread_mutex_unlock(&worker->mutex);
		error = worker->ops.flush(worker->ops.arg);
		/*
		 * Publication is part of ownership.  Keep the ledger entry active
		 * until complete() returns so a lifecycle drain cannot observe zero
		 * pending requests while a used-ring response is still unpublished.
		 */
		worker->ops.complete(worker->ops.arg, job.token, job.epoch, error);
		owner_error = virtio_pmem_async_complete(worker->async, &job);
		pthread_mutex_lock(&worker->mutex);
		(void)pthread_cond_broadcast(&worker->condition);
		/* An impossible owner mismatch deliberately leaves reset fail-closed. */
		if (owner_error != 0)
			continue;
	}
	pthread_mutex_unlock(&worker->mutex);
	return (NULL);
}

int
virtio_pmem_worker_create(size_t capacity,
    const struct virtio_pmem_worker_ops *ops,
    struct virtio_pmem_worker **result)
{
	struct virtio_pmem_worker *worker;
	pthread_condattr_t attr;
	bool attr_initialized, condition_initialized, mutex_initialized;
	int error;

	if (ops == NULL || ops->flush == NULL || ops->complete == NULL ||
	    result == NULL)
		return (EINVAL);
	worker = calloc(1, sizeof(*worker));
	if (worker == NULL)
		return (ENOMEM);
	attr_initialized = false;
	condition_initialized = false;
	mutex_initialized = false;
	error = pthread_mutex_init(&worker->mutex, NULL);
	if (error != 0)
		goto fail;
	mutex_initialized = true;
	error = pthread_condattr_init(&attr);
	if (error != 0)
		goto fail;
	attr_initialized = true;
	error = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
	if (error != 0)
		goto fail;
	error = pthread_cond_init(&worker->condition, &attr);
	if (error != 0)
		goto fail;
	condition_initialized = true;
	(void)pthread_condattr_destroy(&attr);
	attr_initialized = false;
	error = virtio_pmem_async_create(capacity, &worker->async);
	if (error != 0)
		goto fail;
	worker->ops = *ops;
	error = pthread_create(&worker->thread, NULL, virtio_pmem_worker_main,
	    worker);
	if (error != 0)
		goto fail;
	*result = worker;
	return (0);

fail:
	if (worker->async != NULL)
		(void)virtio_pmem_async_destroy(worker->async);
	if (condition_initialized)
		(void)pthread_cond_destroy(&worker->condition);
	if (attr_initialized)
		(void)pthread_condattr_destroy(&attr);
	if (mutex_initialized)
		(void)pthread_mutex_destroy(&worker->mutex);
	free(worker);
	return (error);
}

int
virtio_pmem_worker_submit(struct virtio_pmem_worker *worker, uintptr_t token,
    uint64_t *epoch)
{
	int error;

	if (worker == NULL)
		return (EINVAL);
	error = virtio_pmem_async_submit(worker->async, token, epoch);
	if (error != 0)
		return (error);
	pthread_mutex_lock(&worker->mutex);
	(void)pthread_cond_signal(&worker->condition);
	pthread_mutex_unlock(&worker->mutex);
	return (0);
}

int
virtio_pmem_worker_pause(struct virtio_pmem_worker *worker,
    uint32_t timeout_ms)
{
	struct timespec deadline;
	bool accepting;
	size_t pending;
	int error;

	if (worker == NULL)
		return (EINVAL);
	error = virtio_pmem_async_pause(worker->async, &pending);
	if (error == 0)
		return (0);
	if (error != EINPROGRESS)
		return (error);
	error = virtio_pmem_worker_deadline(timeout_ms, &deadline);
	if (error != 0)
		return (error);
	pthread_mutex_lock(&worker->mutex);
	for (;;) {
		error = virtio_pmem_async_pending(worker->async, &pending,
		    &accepting);
		if (error != 0)
			break;
		if (pending == 0) {
			error = 0;
			break;
		}
		error = pthread_cond_timedwait(&worker->condition, &worker->mutex,
		    &deadline);
		if (error != 0)
			break;
	}
	pthread_mutex_unlock(&worker->mutex);
	return (error);
}

int
virtio_pmem_worker_abort_pause(struct virtio_pmem_worker *worker)
{

	if (worker == NULL)
		return (EINVAL);
	return (virtio_pmem_async_abort_pause(worker->async));
}

int
virtio_pmem_worker_resume(struct virtio_pmem_worker *worker)
{

	if (worker == NULL)
		return (EINVAL);
	return (virtio_pmem_async_resume(worker->async));
}

int
virtio_pmem_worker_reset(struct virtio_pmem_worker *worker,
    uint32_t timeout_ms, bool resume)
{
	int error;

	error = virtio_pmem_worker_pause(worker, timeout_ms);
	if (error != 0)
		return (error);
	return (virtio_pmem_async_finish_reset(worker->async, resume));
}

int
virtio_pmem_worker_defer_reset(struct virtio_pmem_worker *worker, bool resume)
{

	if (worker == NULL)
		return (EINVAL);
	return (virtio_pmem_async_defer_reset(worker->async, resume));
}

int
virtio_pmem_worker_pending(struct virtio_pmem_worker *worker, size_t *pending,
    bool *accepting)
{

	if (worker == NULL)
		return (EINVAL);
	return (virtio_pmem_async_pending(worker->async, pending, accepting));
}

int
virtio_pmem_worker_destroy(struct virtio_pmem_worker *worker,
    uint32_t timeout_ms)
{
	int error;

	if (worker == NULL)
		return (EINVAL);
	error = virtio_pmem_worker_pause(worker, timeout_ms);
	if (error != 0)
		return (error);
	pthread_mutex_lock(&worker->mutex);
	worker->exiting = true;
	(void)pthread_cond_signal(&worker->condition);
	pthread_mutex_unlock(&worker->mutex);
	error = pthread_join(worker->thread, NULL);
	if (error != 0)
		return (error);
	error = virtio_pmem_async_destroy(worker->async);
	if (error != 0)
		return (error);
	(void)pthread_cond_destroy(&worker->condition);
	(void)pthread_mutex_destroy(&worker->mutex);
	free(worker);
	return (0);
}
