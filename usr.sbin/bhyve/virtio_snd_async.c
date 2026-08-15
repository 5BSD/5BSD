/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/errno.h>
#include <sys/uio.h>

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "virtio_snd_async.h"

struct virtio_snd_async_job {
	uint8_t		*buffer;
	size_t		length;
	size_t		offset;
	uintptr_t	token;
	uint64_t	generation;
	enum virtio_snd_async_direction direction;
	bool		active;
};

struct virtio_snd_async {
	pthread_mutex_t mutex;
	struct virtio_snd_async_ops ops;
	struct virtio_snd_async_job jobs[BHYVE_VTSND_ASYNC_STREAMS];
	/* A backend progress callback owns this job while the mutex is dropped. */
	bool progressing[BHYVE_VTSND_ASYNC_STREAMS];
	bool completing[BHYVE_VTSND_ASYNC_STREAMS];
	bool quiescing;
	size_t max_bytes;
};

static bool
vtsnda_direction_valid(enum virtio_snd_async_direction direction)
{

	return (direction == BHYVE_VTSND_ASYNC_PLAYBACK ||
	    direction == BHYVE_VTSND_ASYNC_CAPTURE);
}

static void
vtsnda_job_clear(struct virtio_snd_async_job *job)
{

	memset(job, 0, sizeof(*job));
}

/*
 * On success ownership of buffer transfers to async.  On failure it remains
 * with the caller, which makes admission atomic without an extra hot-path
 * payload copy.
 */
static int
vtsnda_submit_buffer(struct virtio_snd_async *async, uint32_t stream_id,
    enum virtio_snd_async_direction direction, uintptr_t token,
    uint64_t generation, uint8_t *buffer, size_t length)
{
	struct virtio_snd_async_job *job;

	pthread_mutex_lock(&async->mutex);
	job = &async->jobs[stream_id];
	if (async->quiescing || job->active || async->progressing[stream_id] ||
	    async->completing[stream_id]) {
		pthread_mutex_unlock(&async->mutex);
		return (EBUSY);
	}
	job->buffer = buffer;
	job->length = length;
	job->offset = 0;
	job->token = token;
	job->generation = generation;
	job->direction = direction;
	job->active = true;
	pthread_mutex_unlock(&async->mutex);
	return (0);
}

int
virtio_snd_async_create(const struct virtio_snd_async_ops *ops,
    size_t max_bytes, struct virtio_snd_async **result)
{
	struct virtio_snd_async *async;
	int error;

	if (ops == NULL || ops->progress == NULL || ops->complete == NULL ||
	    result == NULL || max_bytes == 0)
		return (EINVAL);
	async = calloc(1, sizeof(*async));
	if (async == NULL)
		return (ENOMEM);
	error = pthread_mutex_init(&async->mutex, NULL);
	if (error != 0) {
		free(async);
		return (error);
	}
	async->ops = *ops;
	async->max_bytes = max_bytes;
	*result = async;
	return (0);
}

int
virtio_snd_async_destroy(struct virtio_snd_async *async)
{
	int error;

	if (async == NULL)
		return (EINVAL);
	pthread_mutex_lock(&async->mutex);
	for (uint32_t stream_id = 0;
	    stream_id < BHYVE_VTSND_ASYNC_STREAMS; stream_id++) {
		if (async->jobs[stream_id].active || async->progressing[stream_id] ||
		    async->completing[stream_id]) {
			pthread_mutex_unlock(&async->mutex);
			return (EBUSY);
		}
	}
	pthread_mutex_unlock(&async->mutex);
	error = pthread_mutex_destroy(&async->mutex);
	if (error != 0)
		return (error);
	free(async);
	return (0);
}

int
virtio_snd_async_submit(struct virtio_snd_async *async, uint32_t stream_id,
    enum virtio_snd_async_direction direction, uintptr_t token,
    uint64_t generation, const void *payload, size_t length)
{
	uint8_t *buffer;
	int error;

	if (async == NULL || stream_id >= BHYVE_VTSND_ASYNC_STREAMS ||
	    !vtsnda_direction_valid(direction) || token == 0 ||
	    generation == 0 || length == 0 || length > async->max_bytes ||
	    (direction == BHYVE_VTSND_ASYNC_PLAYBACK && payload == NULL) ||
	    (direction == BHYVE_VTSND_ASYNC_CAPTURE && payload != NULL))
		return (EINVAL);
	buffer = malloc(length);
	if (buffer == NULL)
		return (ENOMEM);
	if (direction == BHYVE_VTSND_ASYNC_PLAYBACK)
		memcpy(buffer, payload, length);
	else
		memset(buffer, 0, length);
	error = vtsnda_submit_buffer(async, stream_id, direction, token,
	    generation, buffer, length);
	if (error != 0)
		free(buffer);
	return (error);
}

int
virtio_snd_async_submit_iov(struct virtio_snd_async *async,
    uint32_t stream_id, enum virtio_snd_async_direction direction,
    uintptr_t token, uint64_t generation, const struct iovec *iov,
    size_t niov, size_t offset, size_t length)
{
	uint8_t *buffer;
	size_t copied, total;
	int error;

	if (async == NULL || stream_id >= BHYVE_VTSND_ASYNC_STREAMS ||
	    direction != BHYVE_VTSND_ASYNC_PLAYBACK || token == 0 ||
	    generation == 0 || iov == NULL || niov == 0 || length == 0 ||
	    length > async->max_bytes)
		return (EINVAL);
	total = 0;
	for (size_t i = 0; i < niov; i++) {
		if (iov[i].iov_base == NULL || iov[i].iov_len == 0 ||
		    iov[i].iov_len > SIZE_MAX - total)
			return (EINVAL);
		total += iov[i].iov_len;
	}
	if (offset > total || length > total - offset)
		return (EMSGSIZE);
	buffer = malloc(length);
	if (buffer == NULL)
		return (ENOMEM);
	copied = 0;
	for (size_t i = 0; i < niov && copied < length; i++) {
		size_t available, chunk;

		if (offset >= iov[i].iov_len) {
			offset -= iov[i].iov_len;
			continue;
		}
		available = iov[i].iov_len - offset;
		chunk = available < length - copied ? available :
		    length - copied;
		memcpy(buffer + copied,
		    (const uint8_t *)iov[i].iov_base + offset, chunk);
		copied += chunk;
		offset = 0;
	}
	if (copied != length) {
		free(buffer);
		return (EMSGSIZE);
	}
	error = vtsnda_submit_buffer(async, stream_id, direction, token,
	    generation, buffer, length);
	if (error != 0)
		free(buffer);
	return (error);
}

int
virtio_snd_async_progress(struct virtio_snd_async *async, uint32_t stream_id,
    uint64_t generation)
{
	struct virtio_snd_async_job completed;
	struct virtio_snd_async_job *job;
	enum virtio_snd_async_status status;
	size_t progress, remaining;
	int error;

	if (async == NULL || stream_id >= BHYVE_VTSND_ASYNC_STREAMS ||
	    generation == 0)
		return (EINVAL);
	memset(&completed, 0, sizeof(completed));
	pthread_mutex_lock(&async->mutex);
	job = &async->jobs[stream_id];
	if (async->progressing[stream_id] || async->completing[stream_id]) {
		pthread_mutex_unlock(&async->mutex);
		return (EBUSY);
	}
	if (!job->active) {
		pthread_mutex_unlock(&async->mutex);
		return (ENOENT);
	}
	if (job->generation != generation) {
		pthread_mutex_unlock(&async->mutex);
		return (ESTALE);
	}
	remaining = job->length - job->offset;
	progress = 0;
	/*
	 * A host backend may consult the async owner from its readiness callback.
	 * Pin the job, but do not hold this mutex across that external call: the
	 * progress pin makes cancel, lifecycle quiesce, and destruction fail
	 * closed until the callback returns.
	 */
	async->progressing[stream_id] = true;
	struct virtio_snd_async_ops ops = async->ops;
	enum virtio_snd_async_direction direction = job->direction;
	void *buffer = job->buffer + job->offset;
	pthread_mutex_unlock(&async->mutex);
	error = ops.progress(ops.arg, direction, buffer, remaining, &progress);
	pthread_mutex_lock(&async->mutex);
	job = &async->jobs[stream_id];
	if (!job->active || job->generation != generation) {
		async->progressing[stream_id] = false;
		pthread_mutex_unlock(&async->mutex);
		return (EPROTO);
	}
	if (progress > remaining || (error == EAGAIN && progress != 0) ||
	    (error == 0 && progress == 0)) {
		error = EIO;
		progress = 0;
	}
	if (error == EAGAIN) {
		async->progressing[stream_id] = false;
		pthread_mutex_unlock(&async->mutex);
		return (EAGAIN);
	}
	if (error == 0)
		job->offset += progress;
	if (error == 0 && job->offset != job->length) {
		async->progressing[stream_id] = false;
		pthread_mutex_unlock(&async->mutex);
		return (EINPROGRESS);
	}
	completed = *job;
	vtsnda_job_clear(job);
	async->progressing[stream_id] = false;
	async->completing[stream_id] = true;
	pthread_mutex_unlock(&async->mutex);

	status = error == 0 ? BHYVE_VTSND_ASYNC_OK :
	    BHYVE_VTSND_ASYNC_IO_ERR;
	async->ops.complete(async->ops.arg, completed.token, status,
	    status == BHYVE_VTSND_ASYNC_OK &&
	    completed.direction == BHYVE_VTSND_ASYNC_CAPTURE ?
	    completed.buffer : NULL,
	    status == BHYVE_VTSND_ASYNC_OK &&
	    completed.direction == BHYVE_VTSND_ASYNC_CAPTURE ?
	    completed.length : 0);
	free(completed.buffer);
	pthread_mutex_lock(&async->mutex);
	async->completing[stream_id] = false;
	pthread_mutex_unlock(&async->mutex);
	return (error);
}

int
virtio_snd_async_cancel(struct virtio_snd_async *async, uint32_t stream_id,
    uint64_t generation)
{
	struct virtio_snd_async_job completed;
	struct virtio_snd_async_job *job;

	if (async == NULL || stream_id >= BHYVE_VTSND_ASYNC_STREAMS ||
	    generation == 0)
		return (EINVAL);
	pthread_mutex_lock(&async->mutex);
	job = &async->jobs[stream_id];
	if (async->progressing[stream_id] || async->completing[stream_id]) {
		pthread_mutex_unlock(&async->mutex);
		return (EBUSY);
	}
	if (!job->active) {
		pthread_mutex_unlock(&async->mutex);
		return (ENOENT);
	}
	if (job->generation != generation) {
		pthread_mutex_unlock(&async->mutex);
		return (ESTALE);
	}
	completed = *job;
	vtsnda_job_clear(job);
	async->completing[stream_id] = true;
	pthread_mutex_unlock(&async->mutex);
	async->ops.complete(async->ops.arg, completed.token,
	    BHYVE_VTSND_ASYNC_IO_ERR, NULL, 0);
	free(completed.buffer);
	pthread_mutex_lock(&async->mutex);
	async->completing[stream_id] = false;
	pthread_mutex_unlock(&async->mutex);
	return (0);
}

int
virtio_snd_async_pending(struct virtio_snd_async *async, uint32_t stream_id,
    bool *pending, size_t *remaining)
{
	struct virtio_snd_async_job *job;

	if (async == NULL || stream_id >= BHYVE_VTSND_ASYNC_STREAMS ||
	    pending == NULL || remaining == NULL)
		return (EINVAL);
	pthread_mutex_lock(&async->mutex);
	job = &async->jobs[stream_id];
	*pending = job->active || async->progressing[stream_id] ||
	    async->completing[stream_id];
	*remaining = job->active ? job->length - job->offset : 0;
	pthread_mutex_unlock(&async->mutex);
	return (0);
}

int
virtio_snd_async_quiesce(struct virtio_snd_async *async)
{

	if (async == NULL)
		return (EINVAL);
	pthread_mutex_lock(&async->mutex);
	for (uint32_t stream_id = 0;
	    stream_id < BHYVE_VTSND_ASYNC_STREAMS; stream_id++) {
		if (async->jobs[stream_id].active || async->progressing[stream_id] ||
		    async->completing[stream_id]) {
			pthread_mutex_unlock(&async->mutex);
			return (EBUSY);
		}
	}
	/*
	 * Publish the admission fence while holding the same mutex used by
	 * submit.  A readiness callback may still finish a job which was already
	 * active before this point, but no later guest notification can install a
	 * replacement between the empty observation and its caller's lifecycle
	 * lock acquisition.
	 */
	async->quiescing = true;
	pthread_mutex_unlock(&async->mutex);
	return (0);
}

int
virtio_snd_async_resume(struct virtio_snd_async *async)
{

	if (async == NULL)
		return (EINVAL);
	pthread_mutex_lock(&async->mutex);
	for (uint32_t stream_id = 0;
	    stream_id < BHYVE_VTSND_ASYNC_STREAMS; stream_id++) {
		if (async->jobs[stream_id].active || async->progressing[stream_id] ||
		    async->completing[stream_id]) {
			pthread_mutex_unlock(&async->mutex);
			return (EBUSY);
		}
	}
	async->quiescing = false;
	pthread_mutex_unlock(&async->mutex);
	return (0);
}
