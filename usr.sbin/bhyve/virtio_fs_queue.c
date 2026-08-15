/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/uio.h>

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "virtio_fs_backend.h"
#include "virtio_fs_chain.h"
#include "virtio_fs_dispatch.h"
#include "virtio_fs_outbox.h"
#include "virtio_fs_pending.h"
#include "virtio_fs_queue.h"

#define	VIRTIO_FS_QUEUE_MAX_IOV	1024U

struct virtio_fs_queue_owner {
	struct virtio_fs_chain chain;
	uintptr_t guest_cookie;
	uint32_t queue_id;
	uint8_t *request;
	uint8_t *response;
	bool discard_on_cancel;
	struct iovec iov[];
};

struct virtio_fs_queue_completion {
	uintptr_t guest_cookie;
	size_t used;
	bool publish;
};

struct virtio_fs_queue {
	pthread_mutex_t mutex;
	pthread_mutex_t failure_mutex;
	struct virtio_fs_dispatch *dispatch;
	struct virtio_fs_outbox *outbox;
	struct virtio_fs_pending_result *drain;
	struct virtio_fs_queue_completion *completions;
	uint32_t *active_resets;
	size_t active_reset_count;
	virtio_fs_queue_complete_cb complete;
	void *complete_arg;
	virtio_fs_queue_discard_cb discard;
	void *discard_arg;
	virtio_fs_queue_reset_complete_cb reset_complete;
	void *reset_complete_arg;
	uint32_t maximum_message;
	uint32_t maximum_inflight;
};

struct virtio_fs_queue_publish {
	struct virtio_fs_outbox *outbox;
	uint32_t queue_id;
	bool priority;
};

static int
virtio_fs_queue_publish(void *arg,
    const struct virtio_fs_backend_header *header, const void *payload)
{
	struct virtio_fs_queue_publish *publish;

	publish = arg;
	return (virtio_fs_outbox_enqueue_on(publish->outbox,
	    publish->priority, publish->queue_id, header, payload));
}

static void
virtio_fs_queue_owner_free(struct virtio_fs_queue_owner *owner)
{

	if (owner == NULL)
		return;
	free(owner->response);
	free(owner->request);
	free(owner);
}

static void
virtio_fs_queue_discard_owner(struct virtio_fs_queue *queue,
    uintptr_t guest_cookie)
{
	virtio_fs_queue_discard_cb discard;
	void *discard_arg;

	pthread_mutex_lock(&queue->mutex);
	discard = queue->discard;
	discard_arg = queue->discard_arg;
	pthread_mutex_unlock(&queue->mutex);
	if (discard != NULL)
		discard(discard_arg, guest_cookie);
}

static bool
virtio_fs_queue_reset_active_locked(const struct virtio_fs_queue *queue,
    uint32_t queue_id)
{

	for (size_t i = 0; i < queue->active_reset_count; i++) {
		if (queue->active_resets[i] == queue_id)
			return (true);
	}
	return (false);
}

static int
virtio_fs_queue_reset_add_locked(struct virtio_fs_queue *queue,
    uint32_t queue_id)
{

	if (virtio_fs_queue_reset_active_locked(queue, queue_id))
		return (0);
	if (queue->active_reset_count == queue->maximum_inflight)
		return (ENOSPC);
	queue->active_resets[queue->active_reset_count++] = queue_id;
	return (0);
}

static void
virtio_fs_queue_reset_remove_locked(struct virtio_fs_queue *queue,
    uint32_t queue_id)
{

	for (size_t i = 0; i < queue->active_reset_count; i++) {
		if (queue->active_resets[i] != queue_id)
			continue;
		queue->active_resets[i] =
		    queue->active_resets[--queue->active_reset_count];
		return;
	}
}

static int
virtio_fs_queue_cancel_next_locked(struct virtio_fs_queue *queue,
    uint32_t queue_id)
{
	struct virtio_fs_backend_header cancel;
	struct virtio_fs_queue_publish publish;
	struct virtio_fs_queue_owner *owner;
	uintptr_t owner_cookie;
	int error;

	publish = (struct virtio_fs_queue_publish) {
		.outbox = queue->outbox,
		.queue_id = queue_id,
		.priority = true,
	};
	error = virtio_fs_dispatch_cancel_queue_publish(queue->dispatch,
	    queue_id, virtio_fs_queue_publish, &publish, &cancel,
	    &owner_cookie);
	if (error != 0)
		return (error);
	owner = (struct virtio_fs_queue_owner *)owner_cookie;
	if (owner == NULL || owner->queue_id != queue_id)
		return (EPROTO);
	owner->discard_on_cancel = true;
	return (0);
}

int
virtio_fs_queue_create(const struct virtio_fs_backend_session *backend,
    uint32_t normal_capacity, uint32_t priority_capacity,
    virtio_fs_queue_complete_cb complete, void *complete_arg,
    struct virtio_fs_queue **result)
{
	struct virtio_fs_queue *queue;
	int error;

	if (backend == NULL || complete == NULL || result == NULL)
		return (EINVAL);
	*result = NULL;
	queue = calloc(1, sizeof(*queue));
	if (queue == NULL)
		return (ENOMEM);
	error = pthread_mutex_init(&queue->mutex, NULL);
	if (error != 0)
		goto fail;
	error = pthread_mutex_init(&queue->failure_mutex, NULL);
	if (error != 0)
		goto fail_mutex;
	error = virtio_fs_dispatch_create(backend, &queue->dispatch);
	if (error != 0)
		goto fail_failure_mutex;
	error = virtio_fs_outbox_create(normal_capacity, priority_capacity,
	    backend->maximum_message, backend->maximum_pending_bytes,
	    &queue->outbox);
	if (error != 0)
		goto fail_dispatch;
	queue->drain = calloc(backend->maximum_inflight,
	    sizeof(*queue->drain));
	queue->completions = calloc(backend->maximum_inflight,
	    sizeof(*queue->completions));
	queue->active_resets = calloc(backend->maximum_inflight,
	    sizeof(*queue->active_resets));
	if (queue->drain == NULL || queue->completions == NULL ||
	    queue->active_resets == NULL) {
		error = ENOMEM;
		goto fail_outbox;
	}
	queue->complete = complete;
	queue->complete_arg = complete_arg;
	queue->maximum_message = backend->maximum_message;
	queue->maximum_inflight = backend->maximum_inflight;
	*result = queue;
	return (0);

fail_outbox:
	free(queue->active_resets);
	free(queue->completions);
	free(queue->drain);
	virtio_fs_outbox_destroy(queue->outbox);
fail_dispatch:
	virtio_fs_dispatch_destroy(queue->dispatch);
fail_failure_mutex:
	(void)pthread_mutex_destroy(&queue->failure_mutex);
fail_mutex:
	(void)pthread_mutex_destroy(&queue->mutex);
fail:
	free(queue);
	return (error);
}

void
virtio_fs_queue_destroy(struct virtio_fs_queue *queue)
{
	size_t completed;

	if (queue == NULL)
		return;
	/*
	 * An ordinary reset cannot reclaim requests which have already been
	 * sent to the backend.  Destruction follows a disconnected backend,
	 * so drain every pending owner unconditionally before freeing the
	 * dispatch tables.  This also returns each retained guest chain
	 * through its completion or discard callback.
	 */
	(void)virtio_fs_queue_fail(queue, &completed);
	free(queue->active_resets);
	free(queue->completions);
	free(queue->drain);
	virtio_fs_outbox_destroy(queue->outbox);
	virtio_fs_dispatch_destroy(queue->dispatch);
	(void)pthread_mutex_destroy(&queue->failure_mutex);
	(void)pthread_mutex_destroy(&queue->mutex);
	free(queue);
}

int
virtio_fs_queue_set_reset_complete(struct virtio_fs_queue *queue,
    virtio_fs_queue_reset_complete_cb reset_complete, void *reset_complete_arg)
{

	if (queue == NULL)
		return (EINVAL);
	pthread_mutex_lock(&queue->mutex);
	queue->reset_complete = reset_complete;
	queue->reset_complete_arg = reset_complete_arg;
	pthread_mutex_unlock(&queue->mutex);
	return (0);
}

int
virtio_fs_queue_set_discard(struct virtio_fs_queue *queue,
    virtio_fs_queue_discard_cb discard, void *discard_arg)
{

	if (queue == NULL)
		return (EINVAL);
	pthread_mutex_lock(&queue->mutex);
	queue->discard = discard;
	queue->discard_arg = discard_arg;
	pthread_mutex_unlock(&queue->mutex);
	return (0);
}

int
virtio_fs_queue_submit(struct virtio_fs_queue *queue,
    enum virtio_fs_queue_class queue_class, const struct iovec *iov,
    size_t iov_count, size_t readable_count, size_t writable_count,
    bool ordered, uintptr_t guest_cookie)
{

	return (virtio_fs_queue_submit_on(queue, 0, queue_class, iov,
	    iov_count, readable_count, writable_count, ordered,
	    guest_cookie));
}

int
virtio_fs_queue_submit_on(struct virtio_fs_queue *queue, uint32_t queue_id,
    enum virtio_fs_queue_class queue_class, const struct iovec *iov,
    size_t iov_count, size_t readable_count, size_t writable_count,
    bool ordered, uintptr_t guest_cookie)
{
	struct virtio_fs_backend_header header;
	struct virtio_fs_queue_publish publish;
	struct virtio_fs_queue_owner *owner;
	struct virtio_fs_chain source;
	size_t response_size;
	int error;

	if (queue == NULL || iov_count == 0 ||
	    iov_count > VIRTIO_FS_QUEUE_MAX_IOV)
		return (EINVAL);
	error = virtio_fs_chain_validate(iov, iov_count, readable_count,
	    writable_count, ordered, queue->maximum_message, &source);
	if (error != 0)
		return (error);
	owner = calloc(1, sizeof(*owner) + iov_count * sizeof(*owner->iov));
	if (owner == NULL)
		return (ENOMEM);
	memcpy(owner->iov, iov, iov_count * sizeof(*owner->iov));
	owner->chain = source;
	owner->chain.readable_iov = owner->iov;
	owner->chain.writable_iov = owner->iov + readable_count;
	owner->guest_cookie = guest_cookie;
	owner->queue_id = queue_id;
	owner->request = malloc(source.request_length);
	response_size = MIN(source.response_capacity,
	    (size_t)queue->maximum_message);
	if (response_size != 0)
		owner->response = malloc(response_size);
	if (owner->request == NULL ||
	    (response_size != 0 && owner->response == NULL)) {
		error = ENOMEM;
		goto fail;
	}
	error = virtio_fs_chain_gather(&owner->chain, owner->request,
	    source.request_length);
	if (error != 0)
		goto fail;
	publish = (struct virtio_fs_queue_publish) {
		.outbox = queue->outbox,
		.queue_id = queue_id,
		.priority = queue_class == VIRTIO_FS_QUEUE_HIPRIO,
	};
	pthread_mutex_lock(&queue->mutex);
	error = virtio_fs_dispatch_submit_publish_owned_on(queue->dispatch,
	    queue_class, owner->request, source.request_length, response_size,
	    (uintptr_t)owner, queue_id, virtio_fs_queue_publish, &publish,
	    &header);
	pthread_mutex_unlock(&queue->mutex);
	if (error != 0)
		goto fail;
	return (0);

fail:
	virtio_fs_queue_owner_free(owner);
	return (error);
}

int
virtio_fs_queue_reset_one(struct virtio_fs_queue *queue, uint32_t queue_id,
    size_t *discarded)
{
	struct virtio_fs_queue_completion *completions;
	size_t count, i;
	int error;

	if (queue == NULL || discarded == NULL)
		return (EINVAL);
	*discarded = 0;
	completions = calloc(queue->maximum_inflight, sizeof(*completions));
	if (completions == NULL)
		return (ENOMEM);
	pthread_mutex_lock(&queue->failure_mutex);
	pthread_mutex_lock(&queue->mutex);
	count = queue->maximum_inflight;
	error = virtio_fs_dispatch_reset_queue(queue->dispatch, queue_id,
	    queue->drain, queue->maximum_inflight, &count);
	if (error == EBUSY) {
		error = virtio_fs_queue_reset_add_locked(queue, queue_id);
		if (error == 0)
			error = virtio_fs_queue_cancel_next_locked(queue,
			    queue_id);
		if (error == 0 || error == EALREADY)
			error = EINPROGRESS;
		else if (error == ENOTSUP)
			error = EBUSY;
	}
	if (error == 0) {
		(void)virtio_fs_outbox_reset_queue(queue->outbox, queue_id);
		for (i = 0; i < count; i++) {
			completions[i].guest_cookie =
			    ((struct virtio_fs_queue_owner *)
			    queue->drain[i].owner_cookie)->guest_cookie;
			virtio_fs_queue_owner_free(
			    (struct virtio_fs_queue_owner *)
			    queue->drain[i].owner_cookie);
		}
		*discarded = count;
	}
	if (error != EINPROGRESS)
		virtio_fs_queue_reset_remove_locked(queue, queue_id);
	pthread_mutex_unlock(&queue->mutex);
	pthread_mutex_unlock(&queue->failure_mutex);
	if (error == 0) {
		for (i = 0; i < count; i++)
			virtio_fs_queue_discard_owner(queue,
			    completions[i].guest_cookie);
	}
	free(completions);
	return (error);
}

int
virtio_fs_queue_flush_one(struct virtio_fs_queue *queue, int fd)
{
	struct virtio_fs_backend_header sent;
	struct virtio_fs_queue_owner *owner;
	uintptr_t owner_cookie;
	int error;

	if (queue == NULL)
		return (EINVAL);
	owner = NULL;
	pthread_mutex_lock(&queue->mutex);
	error = virtio_fs_outbox_flush_one(queue->outbox, fd, &sent);
	if (error == 0) {
		if ((sent.flags & VIRTIO_FS_BACKEND_MSG_F_NOREPLY) != 0) {
			error = virtio_fs_dispatch_noreply_sent_owned(
			    queue->dispatch, sent.request_id, sent.incarnation,
			    &owner_cookie);
			if (error == 0)
				owner = (struct virtio_fs_queue_owner *)
				    owner_cookie;
		} else if (sent.type == VIRTIO_FS_BACKEND_REQUEST) {
			error = virtio_fs_dispatch_mark_sent(queue->dispatch,
			    sent.request_id, sent.incarnation);
		} else if (sent.type != VIRTIO_FS_BACKEND_CANCEL) {
			error = EPROTO;
		}
	}
	pthread_mutex_unlock(&queue->mutex);
	if (error != 0)
		return (error);
	if (owner != NULL) {
		queue->complete(queue->complete_arg, owner->guest_cookie, 0);
		virtio_fs_queue_owner_free(owner);
	}
	return (0);
}

int
virtio_fs_queue_receive(struct virtio_fs_queue *queue,
    const struct virtio_fs_backend_header *header, const void *payload,
    size_t payload_len)
{
	struct virtio_fs_queue_owner *owner;
	virtio_fs_queue_reset_complete_cb reset_complete;
	void *reset_complete_arg;
	uintptr_t owner_cookie;
	size_t written;
	bool discard, ignored, retired;
	uint32_t reset_queue_id;
	int error, reset_error;

	if (queue == NULL || header == NULL ||
	    (payload == NULL && payload_len != 0))
		return (EINVAL);
	owner = NULL;
	discard = false;
	ignored = false;
	retired = false;
	reset_queue_id = 0;
	pthread_mutex_lock(&queue->mutex);
	error = virtio_fs_dispatch_owner(queue->dispatch, header->request_id,
	    header->incarnation, &owner_cookie);
	if (error == EALREADY) {
		error = virtio_fs_dispatch_retired_frame(queue->dispatch, header,
		    payload_len);
		ignored = error == 0;
		goto out;
	}
	if (error != 0)
		goto out;
	owner = (struct virtio_fs_queue_owner *)owner_cookie;
	if (owner == NULL) {
		error = EPROTO;
		goto out;
	}
	if (header->type == VIRTIO_FS_BACKEND_CANCEL_REPLY) {
		error = virtio_fs_dispatch_cancel_complete_owned(
		    queue->dispatch, header, owner->response,
		    MIN(owner->chain.response_capacity,
		    (size_t)queue->maximum_message), &written, &owner_cookie);
	} else {
		error = virtio_fs_dispatch_complete_owned(queue->dispatch,
		    header, payload, payload_len, owner->response,
		    MIN(owner->chain.response_capacity,
		    (size_t)queue->maximum_message), &written, &owner_cookie);
	}
	if (error != 0)
		goto out;
	retired = true;
	if ((struct virtio_fs_queue_owner *)owner_cookie != owner) {
		error = EPROTO;
		goto out;
	}
	discard = owner->discard_on_cancel;
	reset_queue_id = owner->queue_id;
	if (!discard)
		error = virtio_fs_chain_scatter(&owner->chain, owner->response,
		    written);
	else
		error = 0;
out:
	pthread_mutex_unlock(&queue->mutex);
	if (error != 0) {
		if (retired)
			virtio_fs_queue_owner_free(owner);
		return (error);
	}
	if (ignored)
		return (0);
	if (discard) {
		virtio_fs_queue_discard_owner(queue, owner->guest_cookie);
		virtio_fs_queue_owner_free(owner);
		/*
		 * A selective reset drains unsent ownership synchronously and
		 * cancels sent requests one at a time.  Re-enter the reset path
		 * after each retired sent request.  The final pass removes any
		 * unsent requests which arrived ahead of the reset fence and
		 * notifies the PCI owner only after no guest-chain ownership
		 * remains for this queue.
		 */
		reset_error = virtio_fs_queue_reset_one(queue, reset_queue_id,
		    &written);
		if (reset_error != EINPROGRESS) {
			pthread_mutex_lock(&queue->mutex);
			reset_complete = queue->reset_complete;
			reset_complete_arg = queue->reset_complete_arg;
			pthread_mutex_unlock(&queue->mutex);
			if (reset_complete != NULL)
				reset_complete(reset_complete_arg, reset_queue_id,
				    reset_error);
		}
		return (0);
	}
	queue->complete(queue->complete_arg, owner->guest_cookie, written);
	virtio_fs_queue_owner_free(owner);
	return (0);
}

int
virtio_fs_queue_fail(struct virtio_fs_queue *queue, size_t *completed)
{
	struct virtio_fs_queue_owner *owner;
	virtio_fs_queue_reset_complete_cb reset_complete;
	void *reset_complete_arg;
	uint8_t response[16];
	size_t count, i, published, reset_count;
	uint32_t expected;
	int error, first_error;

	if (queue == NULL || completed == NULL)
		return (EINVAL);
	*completed = 0;
	pthread_mutex_lock(&queue->failure_mutex);
	pthread_mutex_lock(&queue->mutex);
	expected = virtio_fs_dispatch_pending(queue->dispatch);
	count = expected;
	error = virtio_fs_dispatch_disconnect(queue->dispatch, queue->drain,
	    queue->maximum_inflight, &count);
	if (error != 0) {
		pthread_mutex_unlock(&queue->mutex);
		pthread_mutex_unlock(&queue->failure_mutex);
		return (error);
	}
	(void)virtio_fs_outbox_reset(queue->outbox);
	first_error = 0;
	published = 0;
	reset_count = queue->active_reset_count;
	for (i = 0; i < count; i++) {
		owner = (struct virtio_fs_queue_owner *)
		    queue->drain[i].owner_cookie;
		queue->completions[i].guest_cookie = owner->guest_cookie;
		queue->completions[i].used = 0;
		queue->completions[i].publish =
		    !virtio_fs_queue_reset_active_locked(queue,
		    owner->queue_id);
		if (queue->completions[i].publish &&
		    queue->drain[i].request.expects_reply) {
			error = virtio_fs_dispatch_error_response(
			    &queue->drain[i].request, response);
			if (error == 0)
				error = virtio_fs_chain_scatter(&owner->chain,
				    response, sizeof(response));
			if (error == 0)
				queue->completions[i].used =
				    sizeof(response);
			else if (first_error == 0)
				first_error = error;
		}
		if (queue->completions[i].publish)
			published++;
		virtio_fs_queue_owner_free(owner);
	}
	reset_complete = queue->reset_complete;
	reset_complete_arg = queue->reset_complete_arg;
	queue->active_reset_count = 0;
	pthread_mutex_unlock(&queue->mutex);
	for (i = 0; i < count; i++) {
		if (queue->completions[i].publish)
			queue->complete(queue->complete_arg,
			    queue->completions[i].guest_cookie,
			    queue->completions[i].used);
		else
			virtio_fs_queue_discard_owner(queue,
			    queue->completions[i].guest_cookie);
	}
	if (reset_complete != NULL && reset_count != 0) {
		for (i = 0; i < reset_count; i++)
			reset_complete(reset_complete_arg,
			    queue->active_resets[i], EIO);
	}
	pthread_mutex_unlock(&queue->failure_mutex);
	*completed = published;
	return (first_error);
}

int
virtio_fs_queue_pause(struct virtio_fs_queue *queue,
    struct virtio_fs_session *session)
{
	uint32_t pending;
	int error;

	if (queue == NULL || session == NULL)
		return (EINVAL);
	pthread_mutex_lock(&queue->mutex);
	error = virtio_fs_dispatch_pause(queue->dispatch, &pending);
	if (error == EBUSY)
		error = EINPROGRESS;
	if (error == 0 &&
	    (virtio_fs_outbox_count(queue->outbox, false) != 0 ||
	    virtio_fs_outbox_count(queue->outbox, true) != 0))
		error = EINPROGRESS;
	if (error == 0)
		error = virtio_fs_dispatch_session_snapshot(queue->dispatch,
		    session);
	/*
	 * EINPROGRESS is an owned drain: admission stays closed while existing
	 * requests and unsent frames make progress.  A later pause call takes
	 * the stable session snapshot once both sets are empty.  Other failures
	 * are transactional and reopen admission.
	 */
	if (error != 0 && error != EINPROGRESS)
		virtio_fs_dispatch_resume(queue->dispatch);
	pthread_mutex_unlock(&queue->mutex);
	return (error);
}

void
virtio_fs_queue_resume(struct virtio_fs_queue *queue)
{

	if (queue == NULL)
		return;
	pthread_mutex_lock(&queue->mutex);
	virtio_fs_dispatch_resume(queue->dispatch);
	pthread_mutex_unlock(&queue->mutex);
}

int
virtio_fs_queue_restore_session(struct virtio_fs_queue *queue,
    const struct virtio_fs_session *session)
{
	int error;

	if (queue == NULL)
		return (EINVAL);
	pthread_mutex_lock(&queue->mutex);
	error = virtio_fs_dispatch_session_restore(queue->dispatch, session);
	pthread_mutex_unlock(&queue->mutex);
	return (error);
}

int
virtio_fs_queue_reset(struct virtio_fs_queue *queue, size_t *discarded)
{
	size_t count, i;
	uint32_t expected;
	int error;

	if (queue == NULL || discarded == NULL)
		return (EINVAL);
	*discarded = 0;
	pthread_mutex_lock(&queue->failure_mutex);
	pthread_mutex_lock(&queue->mutex);
	expected = virtio_fs_dispatch_pending(queue->dispatch);
	count = expected;
	error = virtio_fs_dispatch_reset(queue->dispatch, queue->drain,
	    queue->maximum_inflight, &count);
	if (error == 0) {
		(void)virtio_fs_outbox_reset(queue->outbox);
		queue->active_reset_count = 0;
		for (i = 0; i < count; i++) {
			queue->completions[i].guest_cookie =
			    ((struct virtio_fs_queue_owner *)
			    queue->drain[i].owner_cookie)->guest_cookie;
			virtio_fs_queue_owner_free(
			    (struct virtio_fs_queue_owner *)
			    queue->drain[i].owner_cookie);
		}
		*discarded = count;
	}
	pthread_mutex_unlock(&queue->mutex);
	if (error == 0) {
		for (i = 0; i < count; i++)
			virtio_fs_queue_discard_owner(queue,
			    queue->completions[i].guest_cookie);
	}
	pthread_mutex_unlock(&queue->failure_mutex);
	return (error);
}

uint32_t
virtio_fs_queue_pending(struct virtio_fs_queue *queue)
{
	uint32_t count;

	if (queue == NULL)
		return (0);
	pthread_mutex_lock(&queue->mutex);
	count = virtio_fs_dispatch_pending(queue->dispatch);
	pthread_mutex_unlock(&queue->mutex);
	return (count);
}

uint32_t
virtio_fs_queue_outgoing(struct virtio_fs_queue *queue)
{
	uint32_t count, normal, priority;

	if (queue == NULL)
		return (0);
	pthread_mutex_lock(&queue->mutex);
	priority = virtio_fs_outbox_count(queue->outbox, true);
	normal = virtio_fs_outbox_count(queue->outbox, false);
	count = normal > UINT32_MAX - priority ? UINT32_MAX :
	    normal + priority;
	pthread_mutex_unlock(&queue->mutex);
	return (count);
}
