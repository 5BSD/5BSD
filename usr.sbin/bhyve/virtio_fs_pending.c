/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "virtio_fs_backend.h"
#include "virtio_fs_pending.h"
#include "virtio_state_range.h"

#define	VFS_PENDING_NONE	UINT32_MAX

struct virtio_fs_pending_entry {
	uint64_t request_id;
	uint64_t backend_incarnation;
	struct virtio_fs_request_context request;
	uintptr_t owner_cookie;
	uint32_t payload_len;
	uint32_t queue_id;
	uint32_t next;
	bool cancel_requested;
	bool sent;
	bool allocated;
};

struct virtio_fs_pending {
	pthread_mutex_t mutex;
	struct virtio_fs_pending_entry *entries;
	uint32_t *buckets;
	uint32_t capacity;
	uint32_t bucket_count;
	uint32_t count;
	uint32_t free_head;
	uint32_t maximum_bytes;
	uint64_t bytes;
};

static uint32_t
virtio_fs_pending_hash(const struct virtio_fs_pending *pending,
    uint64_t request_id)
{
	uint64_t mixed;

	mixed = request_id;
	mixed ^= mixed >> 33;
	mixed *= UINT64_C(0xff51afd7ed558ccd);
	mixed ^= mixed >> 33;
	return ((uint32_t)mixed & (pending->bucket_count - 1));
}

static uint32_t
virtio_fs_pending_find_locked(const struct virtio_fs_pending *pending,
    uint64_t request_id, uint32_t *previous)
{
	uint32_t bucket, index, prior;

	bucket = virtio_fs_pending_hash(pending, request_id);
	prior = VFS_PENDING_NONE;
	for (index = pending->buckets[bucket]; index != VFS_PENDING_NONE;
	    index = pending->entries[index].next) {
		if (pending->entries[index].request_id == request_id) {
			if (previous != NULL)
				*previous = prior;
			return (index);
		}
		prior = index;
	}
	if (previous != NULL)
		*previous = VFS_PENDING_NONE;
	return (VFS_PENDING_NONE);
}

int
virtio_fs_pending_create(uint32_t capacity, uint32_t maximum_bytes,
    struct virtio_fs_pending **result)
{
	struct virtio_fs_pending *pending;
	uint32_t bucket_count, i;
	int error;

	if (result == NULL || capacity == 0 ||
	    capacity > VIRTIO_FS_BACKEND_MAX_INFLIGHT ||
	    maximum_bytes == 0 ||
	    maximum_bytes > VIRTIO_FS_BACKEND_MAX_PENDING_BYTES)
		return (EINVAL);
	*result = NULL;
	bucket_count = 1;
	while (bucket_count < capacity * 2U)
		bucket_count <<= 1;
	pending = calloc(1, sizeof(*pending));
	if (pending == NULL)
		return (ENOMEM);
	pending->entries = calloc(capacity, sizeof(*pending->entries));
	pending->buckets = calloc(bucket_count, sizeof(*pending->buckets));
	if (pending->entries == NULL || pending->buckets == NULL) {
		free(pending->buckets);
		free(pending->entries);
		free(pending);
		return (ENOMEM);
	}
	error = pthread_mutex_init(&pending->mutex, NULL);
	if (error != 0) {
		free(pending->buckets);
		free(pending->entries);
		free(pending);
		return (error);
	}
	pending->capacity = capacity;
	pending->bucket_count = bucket_count;
	pending->maximum_bytes = maximum_bytes;
	memset(pending->buckets, 0xff,
	    bucket_count * sizeof(*pending->buckets));
	for (i = 0; i < capacity; i++)
		pending->entries[i].next = i + 1 == capacity ?
		    VFS_PENDING_NONE : i + 1;
	pending->free_head = 0;
	*result = pending;
	return (0);
}

void
virtio_fs_pending_destroy(struct virtio_fs_pending *pending)
{

	if (pending == NULL)
		return;
	(void)pthread_mutex_destroy(&pending->mutex);
	free(pending->buckets);
	free(pending->entries);
	free(pending);
}

int
virtio_fs_pending_insert(struct virtio_fs_pending *pending,
    uint64_t request_id, uint64_t backend_incarnation,
    const struct virtio_fs_request_context *request, uint32_t payload_len)
{

	return (virtio_fs_pending_insert_owned(pending, request_id,
	    backend_incarnation, request, payload_len, 0));
}

int
virtio_fs_pending_insert_owned(struct virtio_fs_pending *pending,
    uint64_t request_id, uint64_t backend_incarnation,
    const struct virtio_fs_request_context *request, uint32_t payload_len,
    uintptr_t owner_cookie)
{

	return (virtio_fs_pending_insert_owned_on(pending, request_id,
	    backend_incarnation, request, payload_len, owner_cookie, 0));
}

int
virtio_fs_pending_insert_owned_on(struct virtio_fs_pending *pending,
    uint64_t request_id, uint64_t backend_incarnation,
    const struct virtio_fs_request_context *request, uint32_t payload_len,
    uintptr_t owner_cookie, uint32_t queue_id)
{
	struct virtio_fs_pending_entry *entry;
	uint32_t bucket, index;

	if (pending == NULL || request == NULL || request_id == 0 ||
	    backend_incarnation == 0 || request->unique == 0 ||
	    request->incarnation == 0 ||
	    (request->byte_order != VIRTIO_FS_BYTE_ORDER_LITTLE &&
	    request->byte_order != VIRTIO_FS_BYTE_ORDER_BIG) ||
	    request->initializes != (request->init_major != 0) ||
	    payload_len == 0 ||
	    payload_len > VIRTIO_FS_BACKEND_MAX_FRAME)
		return (EINVAL);
	pthread_mutex_lock(&pending->mutex);
	if (virtio_fs_pending_find_locked(pending, request_id, NULL) !=
	    VFS_PENDING_NONE) {
		pthread_mutex_unlock(&pending->mutex);
		return (EEXIST);
	}
	if (pending->free_head == VFS_PENDING_NONE) {
		pthread_mutex_unlock(&pending->mutex);
		return (ENOSPC);
	}
	if (payload_len > pending->maximum_bytes - pending->bytes) {
		pthread_mutex_unlock(&pending->mutex);
		return (ENOBUFS);
	}
	index = pending->free_head;
	entry = &pending->entries[index];
	pending->free_head = entry->next;
	bucket = virtio_fs_pending_hash(pending, request_id);
	entry->request_id = request_id;
	entry->backend_incarnation = backend_incarnation;
	entry->request = *request;
	entry->owner_cookie = owner_cookie;
	entry->payload_len = payload_len;
	entry->queue_id = queue_id;
	entry->cancel_requested = false;
	entry->sent = false;
	entry->allocated = true;
	entry->next = pending->buckets[bucket];
	pending->buckets[bucket] = index;
	pending->count++;
	pending->bytes += payload_len;
	pthread_mutex_unlock(&pending->mutex);
	return (0);
}

int
virtio_fs_pending_mark_sent(struct virtio_fs_pending *pending,
    uint64_t request_id, uint64_t incarnation)
{
	struct virtio_fs_pending_entry *entry;
	uint32_t index;
	int error;

	if (pending == NULL || request_id == 0 || incarnation == 0)
		return (EINVAL);
	pthread_mutex_lock(&pending->mutex);
	index = virtio_fs_pending_find_locked(pending, request_id, NULL);
	if (index == VFS_PENDING_NONE)
		error = ENOENT;
	else {
		entry = &pending->entries[index];
		if (entry->backend_incarnation != incarnation)
			error = ESTALE;
		else if (entry->sent)
			error = EALREADY;
		else {
			entry->sent = true;
			error = 0;
		}
	}
	pthread_mutex_unlock(&pending->mutex);
	return (error);
}

int
virtio_fs_pending_cancel(struct virtio_fs_pending *pending,
    uint64_t request_id, uint64_t incarnation)
{
	struct virtio_fs_pending_entry *entry;
	uint32_t index;
	int error;

	if (pending == NULL || request_id == 0 || incarnation == 0)
		return (EINVAL);
	pthread_mutex_lock(&pending->mutex);
	index = virtio_fs_pending_find_locked(pending, request_id, NULL);
	if (index == VFS_PENDING_NONE)
		error = ENOENT;
	else {
		entry = &pending->entries[index];
		if (entry->backend_incarnation != incarnation)
			error = ESTALE;
		else if (entry->cancel_requested)
			error = EALREADY;
		else {
			entry->cancel_requested = true;
			error = 0;
		}
	}
	pthread_mutex_unlock(&pending->mutex);
	return (error);
}

int
virtio_fs_pending_cancel_next_queue(struct virtio_fs_pending *pending,
    uint32_t queue_id, struct virtio_fs_pending_result *result)
{
	struct virtio_fs_pending_entry *entry;
	uint32_t i;
	bool waiting;

	if (pending == NULL || result == NULL)
		return (EINVAL);
	pthread_mutex_lock(&pending->mutex);
	waiting = false;
	for (i = 0; i < pending->capacity; i++) {
		entry = &pending->entries[i];
		if (!entry->allocated || entry->queue_id != queue_id ||
		    !entry->sent)
			continue;
		if (entry->cancel_requested) {
			waiting = true;
			continue;
		}
		entry->cancel_requested = true;
		*result = (struct virtio_fs_pending_result) {
			.request_id = entry->request_id,
			.backend_incarnation = entry->backend_incarnation,
			.request = entry->request,
			.owner_cookie = entry->owner_cookie,
			.payload_len = entry->payload_len,
			.queue_id = entry->queue_id,
			.cancel_requested = true,
			.sent = true,
		};
		pthread_mutex_unlock(&pending->mutex);
		return (0);
	}
	pthread_mutex_unlock(&pending->mutex);
	return (waiting ? EALREADY : ENOENT);
}

int
virtio_fs_pending_cancel_rollback(struct virtio_fs_pending *pending,
    uint64_t request_id, uint64_t incarnation)
{
	struct virtio_fs_pending_entry *entry;
	uint32_t index;
	int error;

	if (pending == NULL || request_id == 0 || incarnation == 0)
		return (EINVAL);
	pthread_mutex_lock(&pending->mutex);
	index = virtio_fs_pending_find_locked(pending, request_id, NULL);
	if (index == VFS_PENDING_NONE)
		error = ENOENT;
	else {
		entry = &pending->entries[index];
		if (entry->backend_incarnation != incarnation)
			error = ESTALE;
		else if (!entry->cancel_requested)
			error = EALREADY;
		else {
			entry->cancel_requested = false;
			error = 0;
		}
	}
	pthread_mutex_unlock(&pending->mutex);
	return (error);
}

int
virtio_fs_pending_lookup(struct virtio_fs_pending *pending,
    uint64_t request_id, uint64_t incarnation,
    struct virtio_fs_pending_result *result)
{
	struct virtio_fs_pending_entry *entry;
	uint32_t index;

	if (pending == NULL || result == NULL || request_id == 0 ||
	    incarnation == 0)
		return (EINVAL);
	pthread_mutex_lock(&pending->mutex);
	index = virtio_fs_pending_find_locked(pending, request_id, NULL);
	if (index == VFS_PENDING_NONE) {
		pthread_mutex_unlock(&pending->mutex);
		return (ENOENT);
	}
	entry = &pending->entries[index];
	if (entry->backend_incarnation != incarnation) {
		pthread_mutex_unlock(&pending->mutex);
		return (ESTALE);
	}
	*result = (struct virtio_fs_pending_result) {
		.request_id = entry->request_id,
		.backend_incarnation = entry->backend_incarnation,
		.request = entry->request,
		.owner_cookie = entry->owner_cookie,
		.payload_len = entry->payload_len,
		.queue_id = entry->queue_id,
		.cancel_requested = entry->cancel_requested,
		.sent = entry->sent,
	};
	pthread_mutex_unlock(&pending->mutex);
	return (0);
}

int
virtio_fs_pending_remove(struct virtio_fs_pending *pending,
    uint64_t request_id, uint64_t incarnation,
    struct virtio_fs_pending_result *result)
{
	struct virtio_fs_pending_entry *entry;
	uint32_t bucket, index, previous;

	if (pending == NULL || result == NULL || request_id == 0 ||
	    incarnation == 0)
		return (EINVAL);
	pthread_mutex_lock(&pending->mutex);
	index = virtio_fs_pending_find_locked(pending, request_id, &previous);
	if (index == VFS_PENDING_NONE) {
		pthread_mutex_unlock(&pending->mutex);
		return (ENOENT);
	}
	entry = &pending->entries[index];
	if (entry->backend_incarnation != incarnation) {
		pthread_mutex_unlock(&pending->mutex);
		return (ESTALE);
	}
	result->request_id = entry->request_id;
	result->backend_incarnation = entry->backend_incarnation;
	result->request = entry->request;
	result->owner_cookie = entry->owner_cookie;
	result->payload_len = entry->payload_len;
	result->queue_id = entry->queue_id;
	result->cancel_requested = entry->cancel_requested;
	result->sent = entry->sent;
	bucket = virtio_fs_pending_hash(pending, request_id);
	if (previous == VFS_PENDING_NONE)
		pending->buckets[bucket] = entry->next;
	else
		pending->entries[previous].next = entry->next;
	memset(entry, 0, sizeof(*entry));
	entry->next = pending->free_head;
	pending->free_head = index;
	pending->count--;
	pending->bytes -= result->payload_len;
	pthread_mutex_unlock(&pending->mutex);
	return (0);
}

uint32_t
virtio_fs_pending_count(struct virtio_fs_pending *pending)
{
	uint32_t count;

	if (pending == NULL)
		return (0);
	pthread_mutex_lock(&pending->mutex);
	count = pending->count;
	pthread_mutex_unlock(&pending->mutex);
	return (count);
}

uint64_t
virtio_fs_pending_bytes(struct virtio_fs_pending *pending)
{
	uint64_t bytes;

	if (pending == NULL)
		return (0);
	pthread_mutex_lock(&pending->mutex);
	bytes = pending->bytes;
	pthread_mutex_unlock(&pending->mutex);
	return (bytes);
}

bool
virtio_fs_pending_state_overlaps(struct virtio_fs_pending *pending,
    const void *buffer, size_t length)
{

	if (pending == NULL || buffer == NULL)
		return (false);
	return (virtio_state_ranges_overlap(buffer, length, pending,
	    sizeof(*pending)) ||
	    virtio_state_ranges_overlap(buffer, length, pending->entries,
	    pending->capacity * sizeof(*pending->entries)) ||
	    virtio_state_ranges_overlap(buffer, length, pending->buckets,
	    pending->bucket_count * sizeof(*pending->buckets)));
}

static bool
virtio_fs_pending_results_invalid(struct virtio_fs_pending *pending,
    struct virtio_fs_pending_result *results, size_t capacity, size_t *count)
{
	size_t results_size;

	if (count == NULL || (results == NULL && capacity != 0) ||
	    capacity > SIZE_MAX / sizeof(*results))
		return (true);
	results_size = capacity * sizeof(*results);
	return (virtio_fs_pending_state_overlaps(pending, results,
	    results_size) ||
	    virtio_fs_pending_state_overlaps(pending, count, sizeof(*count)) ||
	    virtio_state_ranges_overlap(results, results_size, count,
	    sizeof(*count)));
}

int
virtio_fs_pending_drain(struct virtio_fs_pending *pending,
    struct virtio_fs_pending_result *results, size_t capacity,
    size_t *count)
{
	struct virtio_fs_pending_entry *entry;
	size_t output;
	uint32_t i;

	if (pending == NULL ||
	    virtio_fs_pending_results_invalid(pending, results, capacity,
	    count))
		return (EINVAL);
	pthread_mutex_lock(&pending->mutex);
	*count = pending->count;
	if (pending->count == 0) {
		pthread_mutex_unlock(&pending->mutex);
		return (0);
	}
	if (results == NULL || capacity < pending->count) {
		pthread_mutex_unlock(&pending->mutex);
		return (EMSGSIZE);
	}
	output = 0;
	for (i = 0; i < pending->capacity; i++) {
		entry = &pending->entries[i];
		if (!entry->allocated)
			continue;
		results[output++] = (struct virtio_fs_pending_result) {
			.request_id = entry->request_id,
			.backend_incarnation = entry->backend_incarnation,
			.request = entry->request,
			.owner_cookie = entry->owner_cookie,
			.payload_len = entry->payload_len,
			.queue_id = entry->queue_id,
			.cancel_requested = entry->cancel_requested,
			.sent = entry->sent,
		};
	}
	memset(pending->buckets, 0xff,
	    pending->bucket_count * sizeof(*pending->buckets));
	memset(pending->entries, 0,
	    pending->capacity * sizeof(*pending->entries));
	for (i = 0; i < pending->capacity; i++)
		pending->entries[i].next = i + 1 == pending->capacity ?
		    VFS_PENDING_NONE : i + 1;
	pending->free_head = 0;
	pending->count = 0;
	pending->bytes = 0;
	pthread_mutex_unlock(&pending->mutex);
	return (0);
}

int
virtio_fs_pending_drain_queue(struct virtio_fs_pending *pending,
    uint32_t queue_id, struct virtio_fs_pending_result *results,
    size_t capacity, size_t *count)
{
	struct virtio_fs_pending_entry *entry;
	size_t needed, output;
	uint32_t bucket, i, next;
	bool has_sent;

	if (pending == NULL ||
	    virtio_fs_pending_results_invalid(pending, results, capacity,
	    count))
		return (EINVAL);
	pthread_mutex_lock(&pending->mutex);
	needed = 0;
	has_sent = false;
	for (i = 0; i < pending->capacity; i++) {
		if (pending->entries[i].allocated &&
		    pending->entries[i].queue_id == queue_id) {
			needed++;
			has_sent |= pending->entries[i].sent;
		}
	}
	*count = needed;
	if (has_sent) {
		pthread_mutex_unlock(&pending->mutex);
		return (EBUSY);
	}
	if (needed == 0) {
		pthread_mutex_unlock(&pending->mutex);
		return (0);
	}
	if (results == NULL || capacity < needed) {
		pthread_mutex_unlock(&pending->mutex);
		return (EMSGSIZE);
	}
	output = 0;
	for (bucket = 0; bucket < pending->bucket_count; bucket++) {
		i = pending->buckets[bucket];
		pending->buckets[bucket] = VFS_PENDING_NONE;
		while (i != VFS_PENDING_NONE) {
			entry = &pending->entries[i];
			next = entry->next;
			if (entry->queue_id == queue_id) {
				results[output++] =
				    (struct virtio_fs_pending_result) {
					.request_id = entry->request_id,
					.backend_incarnation =
					    entry->backend_incarnation,
					.request = entry->request,
					.owner_cookie = entry->owner_cookie,
					.payload_len = entry->payload_len,
					.queue_id = entry->queue_id,
					.cancel_requested =
					    entry->cancel_requested,
					.sent = entry->sent,
				    };
				pending->count--;
				pending->bytes -= entry->payload_len;
				memset(entry, 0, sizeof(*entry));
				entry->next = pending->free_head;
				pending->free_head = i;
			} else {
				entry->next = pending->buckets[bucket];
				pending->buckets[bucket] = i;
			}
			i = next;
		}
	}
	pthread_mutex_unlock(&pending->mutex);
	return (0);
}
