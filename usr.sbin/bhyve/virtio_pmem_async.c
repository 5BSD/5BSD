/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/errno.h>

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "virtio_pmem_async.h"

struct virtio_pmem_async {
	pthread_mutex_t mutex;
	struct virtio_pmem_async_job *jobs;
	struct virtio_pmem_async_job active;
	size_t capacity;
	size_t head;
	size_t count;
	uint64_t epoch;
	bool accepting;
	bool active_valid;
	bool reset_pending;
	bool reset_resume;
};

static void
virtio_pmem_async_apply_reset(struct virtio_pmem_async *async, bool resume)
{

	/* No owner from the old epoch remains when this helper is called. */
	async->epoch = async->epoch == UINT64_MAX ? 1 : async->epoch + 1;
	async->accepting = resume;
	async->reset_pending = false;
	async->reset_resume = false;
}

static bool
virtio_pmem_async_has_token(const struct virtio_pmem_async *async,
    uintptr_t token)
{

	if (async->active_valid && async->active.token == token)
		return (true);
	for (size_t i = 0; i < async->count; i++) {
		if (async->jobs[(async->head + i) % async->capacity].token == token)
			return (true);
	}
	return (false);
}

int
virtio_pmem_async_create(size_t capacity, struct virtio_pmem_async **result)
{
	struct virtio_pmem_async *async;
	int error;

	if (result == NULL || capacity == 0 ||
	    capacity > BHYVE_VIRTIO_PMEM_ASYNC_MAX)
		return (EINVAL);
	async = calloc(1, sizeof(*async));
	if (async == NULL)
		return (ENOMEM);
	async->jobs = calloc(capacity, sizeof(*async->jobs));
	if (async->jobs == NULL) {
		free(async);
		return (ENOMEM);
	}
	error = pthread_mutex_init(&async->mutex, NULL);
	if (error != 0) {
		free(async->jobs);
		free(async);
		return (error);
	}
	async->capacity = capacity;
	async->epoch = 1;
	async->accepting = true;
	*result = async;
	return (0);
}

int
virtio_pmem_async_destroy(struct virtio_pmem_async *async)
{
	int error;

	if (async == NULL)
		return (EINVAL);
	pthread_mutex_lock(&async->mutex);
	if (async->count != 0 || async->active_valid) {
		pthread_mutex_unlock(&async->mutex);
		return (EBUSY);
	}
	pthread_mutex_unlock(&async->mutex);
	error = pthread_mutex_destroy(&async->mutex);
	if (error != 0)
		return (error);
	free(async->jobs);
	free(async);
	return (0);
}

int
virtio_pmem_async_submit(struct virtio_pmem_async *async, uintptr_t token,
    uint64_t *epoch)
{
	size_t tail;

	if (async == NULL || token == 0 || epoch == NULL)
		return (EINVAL);
	pthread_mutex_lock(&async->mutex);
	if (!async->accepting) {
		pthread_mutex_unlock(&async->mutex);
		return (EBUSY);
	}
	if (virtio_pmem_async_has_token(async, token)) {
		pthread_mutex_unlock(&async->mutex);
		return (EEXIST);
	}
	if (async->count + (async->active_valid ? 1 : 0) ==
	    async->capacity) {
		pthread_mutex_unlock(&async->mutex);
		return (ENOSPC);
	}
	tail = (async->head + async->count) % async->capacity;
	async->jobs[tail] = (struct virtio_pmem_async_job) {
		.token = token,
		.epoch = async->epoch,
	};
	async->count++;
	*epoch = async->epoch;
	pthread_mutex_unlock(&async->mutex);
	return (0);
}

int
virtio_pmem_async_acquire(struct virtio_pmem_async *async,
    struct virtio_pmem_async_job *job)
{

	if (async == NULL || job == NULL)
		return (EINVAL);
	pthread_mutex_lock(&async->mutex);
	if (async->active_valid) {
		pthread_mutex_unlock(&async->mutex);
		return (EBUSY);
	}
	if (async->count == 0) {
		pthread_mutex_unlock(&async->mutex);
		return (EAGAIN);
	}
	async->active = async->jobs[async->head];
	memset(&async->jobs[async->head], 0, sizeof(async->jobs[0]));
	async->head = (async->head + 1) % async->capacity;
	async->count--;
	async->active_valid = true;
	*job = async->active;
	pthread_mutex_unlock(&async->mutex);
	return (0);
}

int
virtio_pmem_async_complete(struct virtio_pmem_async *async,
    const struct virtio_pmem_async_job *job)
{

	if (async == NULL || job == NULL || job->token == 0 || job->epoch == 0)
		return (EINVAL);
	pthread_mutex_lock(&async->mutex);
	if (!async->active_valid) {
		pthread_mutex_unlock(&async->mutex);
		return (ENOENT);
	}
	if (job->token != async->active.token ||
	    job->epoch != async->active.epoch) {
		pthread_mutex_unlock(&async->mutex);
		return (ESTALE);
	}
	memset(&async->active, 0, sizeof(async->active));
	async->active_valid = false;
	if (async->reset_pending && async->count == 0)
		virtio_pmem_async_apply_reset(async, async->reset_resume);
	pthread_mutex_unlock(&async->mutex);
	return (0);
}

int
virtio_pmem_async_pause(struct virtio_pmem_async *async, size_t *pending)
{
	int error;

	if (async == NULL || pending == NULL)
		return (EINVAL);
	pthread_mutex_lock(&async->mutex);
	async->accepting = false;
	*pending = async->count + (async->active_valid ? 1 : 0);
	error = *pending == 0 ? 0 : EINPROGRESS;
	pthread_mutex_unlock(&async->mutex);
	return (error);
}

int
virtio_pmem_async_abort_pause(struct virtio_pmem_async *async)
{

	if (async == NULL)
		return (EINVAL);
	pthread_mutex_lock(&async->mutex);
	if (async->reset_pending) {
		pthread_mutex_unlock(&async->mutex);
		return (EBUSY);
	}
	/*
	 * Checkpoint rollback reopens admission while a request already owned
	 * by the worker finishes.  Capacity accounting includes that active
	 * owner, so reopening cannot exceed the configured ownership bound.
	 */
	async->accepting = true;
	pthread_mutex_unlock(&async->mutex);
	return (0);
}

int
virtio_pmem_async_resume(struct virtio_pmem_async *async)
{

	if (async == NULL)
		return (EINVAL);
	pthread_mutex_lock(&async->mutex);
	if (async->count != 0 || async->active_valid || async->reset_pending) {
		pthread_mutex_unlock(&async->mutex);
		return (EBUSY);
	}
	async->accepting = true;
	pthread_mutex_unlock(&async->mutex);
	return (0);
}

int
virtio_pmem_async_finish_reset(struct virtio_pmem_async *async, bool resume)
{

	if (async == NULL)
		return (EINVAL);
	pthread_mutex_lock(&async->mutex);
	if (async->accepting || async->count != 0 || async->active_valid ||
	    async->reset_pending) {
		pthread_mutex_unlock(&async->mutex);
		return (EBUSY);
	}
	virtio_pmem_async_apply_reset(async, resume);
	pthread_mutex_unlock(&async->mutex);
	return (0);
}

int
virtio_pmem_async_defer_reset(struct virtio_pmem_async *async, bool resume)
{

	if (async == NULL)
		return (EINVAL);
	pthread_mutex_lock(&async->mutex);
	if (async->accepting || async->reset_pending) {
		pthread_mutex_unlock(&async->mutex);
		return (EBUSY);
	}
	if (async->count == 0 && !async->active_valid)
		virtio_pmem_async_apply_reset(async, resume);
	else {
		async->reset_pending = true;
		async->reset_resume = resume;
	}
	pthread_mutex_unlock(&async->mutex);
	return (0);
}

int
virtio_pmem_async_pending(struct virtio_pmem_async *async, size_t *pending,
    bool *accepting)
{

	if (async == NULL || pending == NULL || accepting == NULL)
		return (EINVAL);
	pthread_mutex_lock(&async->mutex);
	*pending = async->count + (async->active_valid ? 1 : 0);
	*accepting = async->accepting;
	pthread_mutex_unlock(&async->mutex);
	return (0);
}
