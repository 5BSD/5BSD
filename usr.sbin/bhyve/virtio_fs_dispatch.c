/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/endian.h>

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "virtio_fs_backend.h"
#include "virtio_fs_dispatch.h"
#include "virtio_fs_host.h"
#include "virtio_fs_pending.h"
#include "virtio_state_range.h"

#define	FUSE_OUT_HEADER_SIZE	16U
#define	FUSE_PROTOCOL_EIO	5
#define	VFS_TOMBSTONE_NONE	UINT32_MAX

struct virtio_fs_dispatch_tombstone {
	uint64_t request_id;
	uint64_t incarnation;
	uint32_t next;
	bool allocated;
};

struct virtio_fs_dispatch {
	pthread_mutex_t mutex;
	struct virtio_fs_session fuse_session;
	struct virtio_fs_pending *pending;
	struct virtio_fs_dispatch_tombstone *tombstones;
	uint32_t *tombstone_buckets;
	uint32_t tombstone_capacity;
	uint32_t tombstone_bucket_count;
	uint32_t tombstone_cursor;
	uint64_t backend_incarnation;
	uint64_t next_request_id;
	uint32_t backend_features;
	uint32_t maximum_message;
	bool accepting;
};

static uint32_t
virtio_fs_dispatch_tombstone_hash(const struct virtio_fs_dispatch *dispatch,
    uint64_t request_id)
{
	uint64_t mixed;

	mixed = request_id;
	mixed ^= mixed >> 33;
	mixed *= UINT64_C(0xff51afd7ed558ccd);
	mixed ^= mixed >> 33;
	return ((uint32_t)mixed & (dispatch->tombstone_bucket_count - 1));
}

static bool
virtio_fs_dispatch_tombstone_contains_locked(
    const struct virtio_fs_dispatch *dispatch, uint64_t request_id,
    uint64_t incarnation)
{
	uint32_t bucket, index;

	bucket = virtio_fs_dispatch_tombstone_hash(dispatch, request_id);
	for (index = dispatch->tombstone_buckets[bucket];
	    index != VFS_TOMBSTONE_NONE;
	    index = dispatch->tombstones[index].next) {
		if (dispatch->tombstones[index].request_id == request_id &&
		    dispatch->tombstones[index].incarnation == incarnation)
			return (true);
	}
	return (false);
}

static void
virtio_fs_dispatch_tombstone_unlink_locked(
    struct virtio_fs_dispatch *dispatch, uint32_t index)
{
	uint32_t bucket, current, previous;

	bucket = virtio_fs_dispatch_tombstone_hash(dispatch,
	    dispatch->tombstones[index].request_id);
	previous = VFS_TOMBSTONE_NONE;
	for (current = dispatch->tombstone_buckets[bucket];
	    current != VFS_TOMBSTONE_NONE;
	    current = dispatch->tombstones[current].next) {
		if (current != index) {
			previous = current;
			continue;
		}
		if (previous == VFS_TOMBSTONE_NONE)
			dispatch->tombstone_buckets[bucket] =
			    dispatch->tombstones[current].next;
		else
			dispatch->tombstones[previous].next =
			    dispatch->tombstones[current].next;
		return;
	}
}

static void
virtio_fs_dispatch_tombstone_add_locked(struct virtio_fs_dispatch *dispatch,
    uint64_t request_id, uint64_t incarnation)
{
	struct virtio_fs_dispatch_tombstone *entry;
	uint32_t bucket, index;

	if (virtio_fs_dispatch_tombstone_contains_locked(dispatch, request_id,
	    incarnation))
		return;
	index = dispatch->tombstone_cursor;
	dispatch->tombstone_cursor =
	    (dispatch->tombstone_cursor + 1) % dispatch->tombstone_capacity;
	entry = &dispatch->tombstones[index];
	if (entry->allocated)
		virtio_fs_dispatch_tombstone_unlink_locked(dispatch, index);
	bucket = virtio_fs_dispatch_tombstone_hash(dispatch, request_id);
	*entry = (struct virtio_fs_dispatch_tombstone) {
		.request_id = request_id,
		.incarnation = incarnation,
		.next = dispatch->tombstone_buckets[bucket],
		.allocated = true,
	};
	dispatch->tombstone_buckets[bucket] = index;
}

static void
virtio_fs_dispatch_tombstone_clear_locked(
    struct virtio_fs_dispatch *dispatch)
{

	memset(dispatch->tombstones, 0, dispatch->tombstone_capacity *
	    sizeof(*dispatch->tombstones));
	memset(dispatch->tombstone_buckets, 0xff,
	    dispatch->tombstone_bucket_count *
	    sizeof(*dispatch->tombstone_buckets));
	dispatch->tombstone_cursor = 0;
}

static bool
virtio_fs_dispatch_state_overlaps(struct virtio_fs_dispatch *dispatch,
    const void *buffer, size_t length)
{

	return (virtio_state_ranges_overlap(buffer, length, dispatch,
	    sizeof(*dispatch)) ||
	    virtio_fs_pending_state_overlaps(dispatch->pending, buffer,
	    length) ||
	    virtio_state_ranges_overlap(buffer, length, dispatch->tombstones,
	    dispatch->tombstone_capacity * sizeof(*dispatch->tombstones)) ||
	    virtio_state_ranges_overlap(buffer, length,
	    dispatch->tombstone_buckets,
	    dispatch->tombstone_bucket_count *
	    sizeof(*dispatch->tombstone_buckets)));
}

static bool
virtio_fs_dispatch_results_invalid(struct virtio_fs_dispatch *dispatch,
    struct virtio_fs_pending_result *results, size_t capacity, size_t *count)
{
	size_t results_size;

	if (count == NULL || (results == NULL && capacity != 0) ||
	    capacity > SIZE_MAX / sizeof(*results))
		return (true);
	results_size = capacity * sizeof(*results);
	return (virtio_fs_dispatch_state_overlaps(dispatch, results,
	    results_size) ||
	    virtio_fs_dispatch_state_overlaps(dispatch, count, sizeof(*count)) ||
	    virtio_state_ranges_overlap(results, results_size, count,
	    sizeof(*count)));
}

int
virtio_fs_dispatch_error_response(
    const struct virtio_fs_request_context *request, uint8_t output[16])
{

	if (request == NULL || output == NULL || request->unique == 0 ||
	    (request->byte_order != VIRTIO_FS_BYTE_ORDER_LITTLE &&
	    request->byte_order != VIRTIO_FS_BYTE_ORDER_BIG))
		return (EINVAL);
	if (virtio_state_ranges_overlap(request, sizeof(*request), output,
	    FUSE_OUT_HEADER_SIZE))
		return (EINVAL);
	if (request->byte_order == VIRTIO_FS_BYTE_ORDER_BIG) {
		be32enc(output, FUSE_OUT_HEADER_SIZE);
		be32enc(output + 4, (uint32_t)-FUSE_PROTOCOL_EIO);
		be64enc(output + 8, request->unique);
	} else {
		le32enc(output, FUSE_OUT_HEADER_SIZE);
		le32enc(output + 4, (uint32_t)-FUSE_PROTOCOL_EIO);
		le64enc(output + 8, request->unique);
	}
	return (0);
}

static int
virtio_fs_dispatch_request_id(struct virtio_fs_dispatch *dispatch,
    uint64_t *request_id)
{

	if (dispatch->next_request_id == 0 ||
	    dispatch->next_request_id > VIRTIO_FS_BACKEND_REQUEST_ID_MAX)
		return (EOVERFLOW);
	*request_id = dispatch->next_request_id++;
	return (0);
}

int
virtio_fs_dispatch_create(
    const struct virtio_fs_backend_session *backend,
    struct virtio_fs_dispatch **result)
{
	struct virtio_fs_dispatch *dispatch;
	uint32_t bucket_count;
	int error;

	if (backend == NULL || result == NULL ||
	    backend->phase != VIRTIO_FS_BACKEND_ACTIVE ||
	    backend->version != VIRTIO_FS_BACKEND_VERSION ||
	    backend->incarnation == 0 ||
	    backend->maximum_message == 0 ||
	    backend->maximum_message > VIRTIO_FS_BACKEND_MAX_FRAME ||
	    backend->maximum_inflight == 0 ||
	    backend->maximum_inflight > VIRTIO_FS_BACKEND_MAX_INFLIGHT ||
	    backend->maximum_pending_bytes < backend->maximum_message ||
	    backend->maximum_pending_bytes >
	    VIRTIO_FS_BACKEND_MAX_PENDING_BYTES)
		return (EINVAL);
	*result = NULL;
	dispatch = calloc(1, sizeof(*dispatch));
	if (dispatch == NULL)
		return (ENOMEM);
	error = pthread_mutex_init(&dispatch->mutex, NULL);
	if (error != 0) {
		free(dispatch);
		return (error);
	}
	error = virtio_fs_pending_create(backend->maximum_inflight,
	    backend->maximum_pending_bytes, &dispatch->pending);
	if (error != 0) {
		(void)pthread_mutex_destroy(&dispatch->mutex);
		free(dispatch);
		return (error);
	}
	bucket_count = 1;
	while (bucket_count < backend->maximum_inflight * 2U)
		bucket_count <<= 1;
	dispatch->tombstones = calloc(backend->maximum_inflight,
	    sizeof(*dispatch->tombstones));
	dispatch->tombstone_buckets = calloc(bucket_count,
	    sizeof(*dispatch->tombstone_buckets));
	if (dispatch->tombstones == NULL ||
	    dispatch->tombstone_buckets == NULL) {
		free(dispatch->tombstone_buckets);
		free(dispatch->tombstones);
		virtio_fs_pending_destroy(dispatch->pending);
		(void)pthread_mutex_destroy(&dispatch->mutex);
		free(dispatch);
		return (ENOMEM);
	}
	dispatch->tombstone_capacity = backend->maximum_inflight;
	dispatch->tombstone_bucket_count = bucket_count;
	virtio_fs_dispatch_tombstone_clear_locked(dispatch);
	dispatch->backend_incarnation = backend->incarnation;
	dispatch->next_request_id = 1;
	dispatch->backend_features = backend->features;
	dispatch->maximum_message = backend->maximum_message;
	dispatch->accepting = true;
	*result = dispatch;
	return (0);
}

void
virtio_fs_dispatch_destroy(struct virtio_fs_dispatch *dispatch)
{

	if (dispatch == NULL)
		return;
	/*
	 * The owner must stop queue and backend workers before destruction.
	 * Disconnect/drain owns completion of any remaining guest chains.
	 */
	virtio_fs_pending_destroy(dispatch->pending);
	free(dispatch->tombstone_buckets);
	free(dispatch->tombstones);
	(void)pthread_mutex_destroy(&dispatch->mutex);
	free(dispatch);
}

int
virtio_fs_dispatch_submit(struct virtio_fs_dispatch *dispatch,
    enum virtio_fs_queue_class queue_class, const void *request,
    size_t request_len, size_t response_capacity,
    struct virtio_fs_backend_header *backend_header)
{

	return (virtio_fs_dispatch_submit_owned(dispatch, queue_class, request,
	    request_len, response_capacity, 0, backend_header));
}

int
virtio_fs_dispatch_submit_owned(struct virtio_fs_dispatch *dispatch,
    enum virtio_fs_queue_class queue_class, const void *request,
    size_t request_len, size_t response_capacity, uintptr_t owner_cookie,
    struct virtio_fs_backend_header *backend_header)
{

	return (virtio_fs_dispatch_submit_publish_owned(dispatch, queue_class,
	    request, request_len, response_capacity, owner_cookie, NULL, NULL,
	    backend_header));
}

int
virtio_fs_dispatch_submit_publish_owned(struct virtio_fs_dispatch *dispatch,
    enum virtio_fs_queue_class queue_class, const void *request,
    size_t request_len, size_t response_capacity, uintptr_t owner_cookie,
    virtio_fs_dispatch_publish_cb publish, void *publish_arg,
    struct virtio_fs_backend_header *backend_header)
{

	return (virtio_fs_dispatch_submit_publish_owned_on(dispatch,
	    queue_class, request, request_len, response_capacity, owner_cookie,
	    0, publish, publish_arg, backend_header));
}

int
virtio_fs_dispatch_submit_publish_owned_on(
    struct virtio_fs_dispatch *dispatch,
    enum virtio_fs_queue_class queue_class, const void *request,
    size_t request_len, size_t response_capacity, uintptr_t owner_cookie,
    uint32_t queue_id, virtio_fs_dispatch_publish_cb publish,
    void *publish_arg, struct virtio_fs_backend_header *backend_header)
{
	struct virtio_fs_request_context context;
	struct virtio_fs_pending_result removed;
	struct virtio_fs_session candidate;
	struct virtio_fs_backend_header header;
	uint64_t request_id;
	int error, remove_error;

	if (dispatch == NULL || backend_header == NULL)
		return (EINVAL);
	if (virtio_fs_dispatch_state_overlaps(dispatch, request, request_len) ||
	    virtio_fs_dispatch_state_overlaps(dispatch, backend_header,
	    sizeof(*backend_header)) ||
	    virtio_state_ranges_overlap(request, request_len, backend_header,
	    sizeof(*backend_header)))
		return (EINVAL);
	pthread_mutex_lock(&dispatch->mutex);
	if (!dispatch->accepting) {
		error = EBUSY;
		goto out;
	}
	if (request_len > dispatch->maximum_message) {
		error = EMSGSIZE;
		goto out;
	}
	candidate = dispatch->fuse_session;
	error = virtio_fs_request_accept(&candidate, queue_class, request,
	    request_len, response_capacity, &context);
	if (error != 0)
		goto out;
	/*
	 * A replacement INIT terminates the old FUSE session.  Do not advance
	 * its incarnation while requests from that session are still owned;
	 * the queue worker can retry this descriptor after they drain.
	 */
	if (context.initializes &&
	    virtio_fs_pending_count(dispatch->pending) != 0) {
		error = EBUSY;
		goto out;
	}
	error = virtio_fs_dispatch_request_id(dispatch, &request_id);
	if (error != 0)
		goto out;
	error = virtio_fs_pending_insert_owned_on(dispatch->pending, request_id,
	    dispatch->backend_incarnation, &context, (uint32_t)request_len,
	    owner_cookie, queue_id);
	if (error != 0)
		goto out;
	/*
	 * Publish the FUSE session transition only after request ownership is
	 * reserved.  A saturated backend therefore cannot half-accept INIT.
	 */
	header = (struct virtio_fs_backend_header) {
		.version = VIRTIO_FS_BACKEND_VERSION,
		.type = VIRTIO_FS_BACKEND_REQUEST,
		.flags = context.expects_reply ? 0 :
		    VIRTIO_FS_BACKEND_MSG_F_NOREPLY,
		.payload_len = (uint32_t)request_len,
		.request_id = request_id,
		.incarnation = dispatch->backend_incarnation,
	};
	if (publish != NULL) {
		error = publish(publish_arg, &header, request);
		if (error != 0) {
			remove_error = virtio_fs_pending_remove(dispatch->pending,
			    request_id, dispatch->backend_incarnation, &removed);
			if (remove_error != 0)
				error = remove_error;
			goto out;
		}
	}
	dispatch->fuse_session = candidate;
	*backend_header = header;
	error = 0;
out:
	pthread_mutex_unlock(&dispatch->mutex);
	return (error);
}

int
virtio_fs_dispatch_reset_queue(struct virtio_fs_dispatch *dispatch,
    uint32_t queue_id, struct virtio_fs_pending_result *results,
    size_t capacity, size_t *count)
{
	bool resets_session;
	size_t i;
	int error;

	if (dispatch == NULL ||
	    virtio_fs_dispatch_results_invalid(dispatch, results, capacity,
	    count))
		return (EINVAL);
	pthread_mutex_lock(&dispatch->mutex);
	error = virtio_fs_pending_drain_queue(dispatch->pending, queue_id,
	    results, capacity, count);
	if (error == 0) {
		resets_session = false;
		for (i = 0; i < *count; i++)
			resets_session |= results[i].request.initializes;
		if (resets_session)
			virtio_fs_session_reset(&dispatch->fuse_session);
	}
	pthread_mutex_unlock(&dispatch->mutex);
	return (error);
}

int
virtio_fs_dispatch_owner(struct virtio_fs_dispatch *dispatch,
    uint64_t request_id, uint64_t backend_incarnation,
    uintptr_t *owner_cookie)
{
	struct virtio_fs_pending_result pending;
	int error;

	if (dispatch == NULL || owner_cookie == NULL)
		return (EINVAL);
	if (virtio_fs_dispatch_state_overlaps(dispatch, owner_cookie,
	    sizeof(*owner_cookie)))
		return (EINVAL);
	pthread_mutex_lock(&dispatch->mutex);
	error = virtio_fs_pending_lookup(dispatch->pending, request_id,
	    backend_incarnation, &pending);
	if (error == ENOENT &&
	    virtio_fs_dispatch_tombstone_contains_locked(dispatch, request_id,
	    backend_incarnation))
		error = EALREADY;
	if (error == 0)
		*owner_cookie = pending.owner_cookie;
	pthread_mutex_unlock(&dispatch->mutex);
	return (error);
}

int
virtio_fs_dispatch_complete(struct virtio_fs_dispatch *dispatch,
    const struct virtio_fs_backend_header *backend_header,
    const void *backend_payload, size_t backend_payload_len,
    void *guest_response, size_t guest_capacity, size_t *guest_written)
{
	uintptr_t owner_cookie;

	return (virtio_fs_dispatch_complete_owned(dispatch, backend_header,
	    backend_payload, backend_payload_len, guest_response,
	    guest_capacity, guest_written, &owner_cookie));
}

int
virtio_fs_dispatch_complete_owned(struct virtio_fs_dispatch *dispatch,
    const struct virtio_fs_backend_header *backend_header,
    const void *backend_payload, size_t backend_payload_len,
    void *guest_response, size_t guest_capacity, size_t *guest_written,
    uintptr_t *owner_cookie)
{
	struct virtio_fs_pending_result pending;
	uint8_t error_response[FUSE_OUT_HEADER_SIZE];
	uint8_t header_wire[VIRTIO_FS_BACKEND_HEADER_SIZE];
	const void *response;
	size_t response_len;
	int error;

	if (dispatch == NULL || backend_header == NULL ||
	    guest_written == NULL || owner_cookie == NULL ||
	    (backend_payload == NULL && backend_payload_len != 0) ||
	    (guest_response == NULL && guest_capacity != 0))
		return (EINVAL);
	if (virtio_fs_dispatch_state_overlaps(dispatch, backend_header,
	    sizeof(*backend_header)) ||
	    virtio_fs_dispatch_state_overlaps(dispatch, backend_payload,
	    backend_payload_len) ||
	    virtio_fs_dispatch_state_overlaps(dispatch, guest_response,
	    guest_capacity) ||
	    virtio_fs_dispatch_state_overlaps(dispatch, guest_written,
	    sizeof(*guest_written)) ||
	    virtio_fs_dispatch_state_overlaps(dispatch, owner_cookie,
	    sizeof(*owner_cookie)) ||
	    virtio_state_ranges_overlap(guest_response, guest_capacity,
	    guest_written, sizeof(*guest_written)) ||
	    virtio_state_ranges_overlap(guest_response, guest_capacity,
	    owner_cookie, sizeof(*owner_cookie)) ||
	    virtio_state_ranges_overlap(guest_written, sizeof(*guest_written),
	    owner_cookie, sizeof(*owner_cookie)) ||
	    virtio_state_ranges_overlap(backend_header,
	    sizeof(*backend_header), guest_response, guest_capacity) ||
	    virtio_state_ranges_overlap(backend_header,
	    sizeof(*backend_header), guest_written, sizeof(*guest_written)) ||
	    virtio_state_ranges_overlap(backend_header,
	    sizeof(*backend_header), owner_cookie, sizeof(*owner_cookie)) ||
	    virtio_state_ranges_overlap(backend_payload, backend_payload_len,
	    guest_response, guest_capacity) ||
	    virtio_state_ranges_overlap(backend_payload, backend_payload_len,
	    guest_written, sizeof(*guest_written)) ||
	    virtio_state_ranges_overlap(backend_payload, backend_payload_len,
	    owner_cookie, sizeof(*owner_cookie)))
		return (EINVAL);
	*guest_written = 0;
	*owner_cookie = 0;
	if (virtio_fs_backend_header_encode(backend_header, header_wire) != 0 ||
	    backend_header->type != VIRTIO_FS_BACKEND_RESPONSE ||
	    backend_header->payload_len != backend_payload_len ||
	    backend_payload_len > dispatch->maximum_message)
		return (EPROTO);
	pthread_mutex_lock(&dispatch->mutex);
	error = virtio_fs_pending_lookup(dispatch->pending,
	    backend_header->request_id, backend_header->incarnation, &pending);
	if (error == ENOENT &&
	    virtio_fs_dispatch_tombstone_contains_locked(dispatch,
	    backend_header->request_id, backend_header->incarnation))
		error = EALREADY;
	if (error != 0)
		goto out;
	if (!pending.request.expects_reply) {
		error = EPROTO;
		goto out;
	}
	if (backend_header->status == 0) {
		response = backend_payload;
		response_len = backend_payload_len;
	} else {
		/*
		 * VFSB status reports backend/transport failure, not a FUSE
		 * operation errno.  Emit the portable FUSE EIO value instead
		 * of leaking host errno numbering into the guest protocol.
		 */
		error = virtio_fs_dispatch_error_response(&pending.request,
		    error_response);
		if (error != 0)
			goto out;
		response = error_response;
		response_len = sizeof(error_response);
	}
	if (response_len > guest_capacity) {
		error = EMSGSIZE;
		goto out;
	}
	error = virtio_fs_response_complete(&dispatch->fuse_session,
	    &pending.request, response, response_len);
	if (error != 0)
		goto out;
	error = virtio_fs_pending_remove(dispatch->pending,
	    backend_header->request_id, backend_header->incarnation, &pending);
	if (error != 0)
		goto out;
	if (pending.cancel_requested)
		virtio_fs_dispatch_tombstone_add_locked(dispatch,
		    pending.request_id, pending.backend_incarnation);
	memcpy(guest_response, response, response_len);
	*guest_written = response_len;
	*owner_cookie = pending.owner_cookie;
out:
	pthread_mutex_unlock(&dispatch->mutex);
	return (error);
}

int
virtio_fs_dispatch_mark_sent(struct virtio_fs_dispatch *dispatch,
    uint64_t request_id, uint64_t backend_incarnation)
{
	int error;

	if (dispatch == NULL)
		return (EINVAL);
	pthread_mutex_lock(&dispatch->mutex);
	error = virtio_fs_pending_mark_sent(dispatch->pending, request_id,
	    backend_incarnation);
	pthread_mutex_unlock(&dispatch->mutex);
	return (error);
}

int
virtio_fs_dispatch_noreply_sent(struct virtio_fs_dispatch *dispatch,
    uint64_t request_id, uint64_t backend_incarnation)
{
	uintptr_t owner_cookie;

	return (virtio_fs_dispatch_noreply_sent_owned(dispatch, request_id,
	    backend_incarnation, &owner_cookie));
}

int
virtio_fs_dispatch_noreply_sent_owned(
    struct virtio_fs_dispatch *dispatch, uint64_t request_id,
    uint64_t backend_incarnation, uintptr_t *owner_cookie)
{
	struct virtio_fs_pending_result pending;
	int error;

	if (dispatch == NULL || owner_cookie == NULL)
		return (EINVAL);
	if (virtio_fs_dispatch_state_overlaps(dispatch, owner_cookie,
	    sizeof(*owner_cookie)))
		return (EINVAL);
	*owner_cookie = 0;
	pthread_mutex_lock(&dispatch->mutex);
	error = virtio_fs_pending_lookup(dispatch->pending, request_id,
	    backend_incarnation, &pending);
	if (error != 0)
		goto out;
	if (pending.request.expects_reply) {
		error = EPROTO;
		goto out;
	}
	error = virtio_fs_response_complete(&dispatch->fuse_session,
	    &pending.request, NULL, 0);
	if (error != 0)
		goto out;
	error = virtio_fs_pending_remove(dispatch->pending, request_id,
	    backend_incarnation, &pending);
	if (error == 0)
		*owner_cookie = pending.owner_cookie;
out:
	pthread_mutex_unlock(&dispatch->mutex);
	return (error);
}

int
virtio_fs_dispatch_cancel(struct virtio_fs_dispatch *dispatch,
    uint64_t request_id, uint64_t backend_incarnation,
    struct virtio_fs_backend_header *backend_header)
{
	struct virtio_fs_pending_result pending;
	int error;

	if (dispatch == NULL || backend_header == NULL)
		return (EINVAL);
	if (virtio_fs_dispatch_state_overlaps(dispatch, backend_header,
	    sizeof(*backend_header)))
		return (EINVAL);
	pthread_mutex_lock(&dispatch->mutex);
	if ((dispatch->backend_features & VIRTIO_FS_BACKEND_F_CANCEL) == 0) {
		error = ENOTSUP;
		goto out;
	}
	error = virtio_fs_pending_cancel(dispatch->pending, request_id,
	    backend_incarnation);
	if (error == EALREADY)
		error = 0;
	if (error != 0)
		goto out;
	error = virtio_fs_pending_lookup(dispatch->pending, request_id,
	    backend_incarnation, &pending);
	if (error != 0)
		goto out;
	*backend_header = (struct virtio_fs_backend_header) {
		.version = VIRTIO_FS_BACKEND_VERSION,
		.type = VIRTIO_FS_BACKEND_CANCEL,
		.request_id = pending.request_id,
		.incarnation = pending.backend_incarnation,
	};
out:
	pthread_mutex_unlock(&dispatch->mutex);
	return (error);
}

int
virtio_fs_dispatch_cancel_queue_publish(
    struct virtio_fs_dispatch *dispatch, uint32_t queue_id,
    virtio_fs_dispatch_publish_cb publish, void *publish_arg,
    struct virtio_fs_backend_header *backend_header,
    uintptr_t *owner_cookie)
{
	struct virtio_fs_pending_result pending;
	struct virtio_fs_backend_header header;
	int error, rollback_error;

	if (dispatch == NULL || publish == NULL || backend_header == NULL ||
	    owner_cookie == NULL)
		return (EINVAL);
	if (virtio_fs_dispatch_state_overlaps(dispatch, backend_header,
	    sizeof(*backend_header)) ||
	    virtio_fs_dispatch_state_overlaps(dispatch, owner_cookie,
	    sizeof(*owner_cookie)) ||
	    virtio_state_ranges_overlap(backend_header,
	    sizeof(*backend_header), owner_cookie, sizeof(*owner_cookie)))
		return (EINVAL);
	*owner_cookie = 0;
	pthread_mutex_lock(&dispatch->mutex);
	if ((dispatch->backend_features & VIRTIO_FS_BACKEND_F_CANCEL) == 0) {
		error = ENOTSUP;
		goto out;
	}
	error = virtio_fs_pending_cancel_next_queue(dispatch->pending,
	    queue_id, &pending);
	if (error != 0)
		goto out;
	header = (struct virtio_fs_backend_header) {
		.version = VIRTIO_FS_BACKEND_VERSION,
		.type = VIRTIO_FS_BACKEND_CANCEL,
		.request_id = pending.request_id,
		.incarnation = pending.backend_incarnation,
	};
	error = publish(publish_arg, &header, NULL);
	if (error != 0) {
		rollback_error = virtio_fs_pending_cancel_rollback(
		    dispatch->pending, pending.request_id,
		    pending.backend_incarnation);
		if (rollback_error != 0)
			error = rollback_error;
		goto out;
	}
	*backend_header = header;
	*owner_cookie = pending.owner_cookie;
out:
	pthread_mutex_unlock(&dispatch->mutex);
	return (error);
}

int
virtio_fs_dispatch_cancel_complete(struct virtio_fs_dispatch *dispatch,
    const struct virtio_fs_backend_header *backend_header,
    void *guest_response, size_t guest_capacity, size_t *guest_written)
{
	uintptr_t owner_cookie;
	int error;

	error = virtio_fs_dispatch_cancel_complete_owned(dispatch,
	    backend_header, guest_response, guest_capacity, guest_written,
	    &owner_cookie);
	return (error == EALREADY ? 0 : error);
}

int
virtio_fs_dispatch_cancel_complete_owned(
    struct virtio_fs_dispatch *dispatch,
    const struct virtio_fs_backend_header *backend_header,
    void *guest_response, size_t guest_capacity, size_t *guest_written,
    uintptr_t *owner_cookie)
{
	struct virtio_fs_pending_result pending;
	uint8_t response[FUSE_OUT_HEADER_SIZE];
	uint8_t header_wire[VIRTIO_FS_BACKEND_HEADER_SIZE];
	bool expects_reply;
	int error;

	if (dispatch == NULL || backend_header == NULL ||
	    guest_written == NULL || owner_cookie == NULL ||
	    (guest_response == NULL && guest_capacity != 0))
		return (EINVAL);
	if (virtio_fs_dispatch_state_overlaps(dispatch, backend_header,
	    sizeof(*backend_header)) ||
	    virtio_fs_dispatch_state_overlaps(dispatch, guest_response,
	    guest_capacity) ||
	    virtio_fs_dispatch_state_overlaps(dispatch, guest_written,
	    sizeof(*guest_written)) ||
	    virtio_fs_dispatch_state_overlaps(dispatch, owner_cookie,
	    sizeof(*owner_cookie)) ||
	    virtio_state_ranges_overlap(guest_response, guest_capacity,
	    guest_written, sizeof(*guest_written)) ||
	    virtio_state_ranges_overlap(guest_response, guest_capacity,
	    owner_cookie, sizeof(*owner_cookie)) ||
	    virtio_state_ranges_overlap(guest_written, sizeof(*guest_written),
	    owner_cookie, sizeof(*owner_cookie)) ||
	    virtio_state_ranges_overlap(backend_header,
	    sizeof(*backend_header), guest_response, guest_capacity) ||
	    virtio_state_ranges_overlap(backend_header,
	    sizeof(*backend_header), guest_written, sizeof(*guest_written)) ||
	    virtio_state_ranges_overlap(backend_header,
	    sizeof(*backend_header), owner_cookie, sizeof(*owner_cookie)))
		return (EINVAL);
	*guest_written = 0;
	*owner_cookie = 0;
	if (virtio_fs_backend_header_encode(backend_header, header_wire) != 0 ||
	    backend_header->type != VIRTIO_FS_BACKEND_CANCEL_REPLY ||
	    backend_header->payload_len != 0)
		return (EPROTO);
	pthread_mutex_lock(&dispatch->mutex);
	error = virtio_fs_pending_lookup(dispatch->pending,
	    backend_header->request_id, backend_header->incarnation, &pending);
	if (error == ENOENT &&
	    virtio_fs_dispatch_tombstone_contains_locked(dispatch,
	    backend_header->request_id, backend_header->incarnation))
		error = EALREADY;
	if (error == 0 && !pending.cancel_requested)
		error = EPROTO;
	if (error != 0)
		goto out;
	expects_reply = pending.request.expects_reply;
	if (backend_header->status != 0) {
		error = EIO;
		goto out;
	}
	if (!expects_reply) {
		error = virtio_fs_response_complete(&dispatch->fuse_session,
		    &pending.request, NULL, 0);
	} else if (guest_capacity < sizeof(response)) {
		error = EMSGSIZE;
	} else {
		error = virtio_fs_dispatch_error_response(&pending.request,
		    response);
		if (error == 0)
			error = virtio_fs_response_complete(
			    &dispatch->fuse_session, &pending.request, response,
			    sizeof(response));
	}
	if (error != 0)
		goto out;
	error = virtio_fs_pending_remove(dispatch->pending,
	    backend_header->request_id, backend_header->incarnation, &pending);
	if (error != 0)
		goto out;
	virtio_fs_dispatch_tombstone_add_locked(dispatch, pending.request_id,
	    pending.backend_incarnation);
	if (expects_reply) {
		memcpy(guest_response, response, sizeof(response));
		*guest_written = sizeof(response);
	}
	*owner_cookie = pending.owner_cookie;
out:
	pthread_mutex_unlock(&dispatch->mutex);
	return (error);
}

int
virtio_fs_dispatch_retired_frame(struct virtio_fs_dispatch *dispatch,
    const struct virtio_fs_backend_header *backend_header,
    size_t backend_payload_len)
{
	uint8_t header_wire[VIRTIO_FS_BACKEND_HEADER_SIZE];
	int error;

	if (dispatch == NULL || backend_header == NULL)
		return (EINVAL);
	if (virtio_fs_backend_header_encode(backend_header, header_wire) != 0 ||
	    (backend_header->type != VIRTIO_FS_BACKEND_RESPONSE &&
	    backend_header->type != VIRTIO_FS_BACKEND_CANCEL_REPLY) ||
	    backend_header->payload_len != backend_payload_len ||
	    (backend_header->type == VIRTIO_FS_BACKEND_CANCEL_REPLY &&
	    backend_payload_len != 0))
		return (EPROTO);
	pthread_mutex_lock(&dispatch->mutex);
	error = virtio_fs_dispatch_tombstone_contains_locked(dispatch,
	    backend_header->request_id, backend_header->incarnation) ? 0 :
	    ENOENT;
	pthread_mutex_unlock(&dispatch->mutex);
	return (error);
}

int
virtio_fs_dispatch_abort(struct virtio_fs_dispatch *dispatch,
    uint64_t request_id, uint64_t backend_incarnation, void *guest_response,
    size_t guest_capacity, size_t *guest_written)
{
	struct virtio_fs_pending_result pending;
	uint8_t response[FUSE_OUT_HEADER_SIZE];
	int error;

	if (dispatch == NULL || guest_written == NULL ||
	    (guest_response == NULL && guest_capacity != 0))
		return (EINVAL);
	if (virtio_fs_dispatch_state_overlaps(dispatch, guest_response,
	    guest_capacity) ||
	    virtio_fs_dispatch_state_overlaps(dispatch, guest_written,
	    sizeof(*guest_written)) ||
	    virtio_state_ranges_overlap(guest_response, guest_capacity,
	    guest_written, sizeof(*guest_written)))
		return (EINVAL);
	*guest_written = 0;
	pthread_mutex_lock(&dispatch->mutex);
	error = virtio_fs_pending_lookup(dispatch->pending, request_id,
	    backend_incarnation, &pending);
	if (error != 0)
		goto out;
	if (!pending.request.expects_reply) {
		error = virtio_fs_response_complete(&dispatch->fuse_session,
		    &pending.request, NULL, 0);
		if (error == 0)
			error = virtio_fs_pending_remove(dispatch->pending,
			    request_id, backend_incarnation, &pending);
		goto out;
	}
	if (guest_capacity < sizeof(response)) {
		error = EMSGSIZE;
		goto out;
	}
	error = virtio_fs_dispatch_error_response(&pending.request, response);
	if (error != 0)
		goto out;
	error = virtio_fs_response_complete(&dispatch->fuse_session,
	    &pending.request, response, sizeof(response));
	if (error == 0) {
		error = virtio_fs_pending_remove(dispatch->pending, request_id,
		    backend_incarnation, &pending);
	}
	if (error == 0) {
		memcpy(guest_response, response, sizeof(response));
		*guest_written = sizeof(response);
	}
out:
	pthread_mutex_unlock(&dispatch->mutex);
	return (error);
}

int
virtio_fs_dispatch_pause(struct virtio_fs_dispatch *dispatch,
    uint32_t *pending_requests)
{

	if (dispatch == NULL || pending_requests == NULL)
		return (EINVAL);
	if (virtio_fs_dispatch_state_overlaps(dispatch, pending_requests,
	    sizeof(*pending_requests)))
		return (EINVAL);
	pthread_mutex_lock(&dispatch->mutex);
	dispatch->accepting = false;
	*pending_requests = virtio_fs_pending_count(dispatch->pending);
	pthread_mutex_unlock(&dispatch->mutex);
	return (*pending_requests == 0 ? 0 : EBUSY);
}

void
virtio_fs_dispatch_resume(struct virtio_fs_dispatch *dispatch)
{

	if (dispatch == NULL)
		return;
	pthread_mutex_lock(&dispatch->mutex);
	if (dispatch->backend_incarnation != 0)
		dispatch->accepting = true;
	pthread_mutex_unlock(&dispatch->mutex);
}

int
virtio_fs_dispatch_session_snapshot(struct virtio_fs_dispatch *dispatch,
    struct virtio_fs_session *session)
{
	int error;

	if (dispatch == NULL || session == NULL)
		return (EINVAL);
	if (virtio_fs_dispatch_state_overlaps(dispatch, session,
	    sizeof(*session)))
		return (EINVAL);
	pthread_mutex_lock(&dispatch->mutex);
	if (dispatch->accepting ||
	    virtio_fs_pending_count(dispatch->pending) != 0)
		error = EBUSY;
	else {
		*session = dispatch->fuse_session;
		error = 0;
	}
	pthread_mutex_unlock(&dispatch->mutex);
	return (error);
}

int
virtio_fs_dispatch_session_restore(struct virtio_fs_dispatch *dispatch,
    const struct virtio_fs_session *session)
{
	int error;

	if (dispatch == NULL || session == NULL ||
	    virtio_fs_dispatch_state_overlaps(dispatch, session,
	    sizeof(*session)) ||
	    session->byte_order > VIRTIO_FS_BYTE_ORDER_BIG ||
	    (session->initialized &&
	    (session->byte_order == VIRTIO_FS_BYTE_ORDER_UNKNOWN ||
	    session->incarnation == 0)))
		return (EINVAL);
	pthread_mutex_lock(&dispatch->mutex);
	if (dispatch->accepting ||
	    virtio_fs_pending_count(dispatch->pending) != 0)
		error = EBUSY;
	else {
		dispatch->fuse_session = *session;
		error = 0;
	}
	pthread_mutex_unlock(&dispatch->mutex);
	return (error);
}

int
virtio_fs_dispatch_reset(struct virtio_fs_dispatch *dispatch,
    struct virtio_fs_pending_result *results, size_t capacity, size_t *count)
{
	int error;

	if (dispatch == NULL ||
	    virtio_fs_dispatch_results_invalid(dispatch, results, capacity,
	    count))
		return (EINVAL);
	pthread_mutex_lock(&dispatch->mutex);
	/*
	 * A guest reset retires guest-chain ownership and the negotiated FUSE
	 * session, but it does not terminate the authenticated backend
	 * connection.  Keep the backend incarnation so a fresh FUSE INIT can
	 * reuse this dispatch object after the reset completes.
	 */
	dispatch->accepting = false;
	error = virtio_fs_pending_drain(dispatch->pending, results, capacity,
	    count);
	if (error == 0) {
		for (size_t i = 0; i < *count; i++) {
			if (results[i].sent && results[i].request.expects_reply)
				virtio_fs_dispatch_tombstone_add_locked(dispatch,
				    results[i].request_id,
				    results[i].backend_incarnation);
		}
		virtio_fs_session_reset(&dispatch->fuse_session);
		dispatch->accepting = dispatch->backend_incarnation != 0;
	}
	pthread_mutex_unlock(&dispatch->mutex);
	return (error);
}

int
virtio_fs_dispatch_disconnect(struct virtio_fs_dispatch *dispatch,
    struct virtio_fs_pending_result *results, size_t capacity, size_t *count)
{
	int error;

	if (dispatch == NULL ||
	    virtio_fs_dispatch_results_invalid(dispatch, results, capacity,
	    count))
		return (EINVAL);
	pthread_mutex_lock(&dispatch->mutex);
	dispatch->accepting = false;
	error = virtio_fs_pending_drain(dispatch->pending, results, capacity,
	    count);
	if (error == 0) {
		dispatch->backend_incarnation = 0;
		virtio_fs_dispatch_tombstone_clear_locked(dispatch);
		virtio_fs_session_reset(&dispatch->fuse_session);
	}
	pthread_mutex_unlock(&dispatch->mutex);
	return (error);
}

uint32_t
virtio_fs_dispatch_pending(struct virtio_fs_dispatch *dispatch)
{
	uint32_t count;

	if (dispatch == NULL)
		return (0);
	pthread_mutex_lock(&dispatch->mutex);
	count = virtio_fs_pending_count(dispatch->pending);
	pthread_mutex_unlock(&dispatch->mutex);
	return (count);
}
