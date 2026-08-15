/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "virtio_fs_backend.h"
#include "virtio_fs_backend_io.h"
#include "virtio_fs_outbox.h"
#include "virtio_state_range.h"

struct virtio_fs_outbox_frame {
	struct virtio_fs_outbox_frame *next;
	struct virtio_fs_backend_header header;
	uint32_t queue_id;
	uint8_t payload[];
};

struct virtio_fs_outbox_lane {
	struct virtio_fs_outbox_frame *head;
	struct virtio_fs_outbox_frame *tail;
	uint32_t count;
	uint32_t capacity;
	uint64_t bytes;
};

struct virtio_fs_outbox {
	pthread_mutex_t mutex;
	struct virtio_fs_outbox_lane normal;
	struct virtio_fs_outbox_lane priority;
	uint32_t maximum_message;
	uint64_t maximum_bytes;
	uint64_t normal_byte_limit;
};

static void
virtio_fs_outbox_lane_free(struct virtio_fs_outbox_lane *lane)
{
	struct virtio_fs_outbox_frame *frame, *next;

	for (frame = lane->head; frame != NULL; frame = next) {
		next = frame->next;
		free(frame);
	}
	memset(lane, 0, sizeof(*lane));
}

int
virtio_fs_outbox_create(uint32_t normal_capacity,
    uint32_t priority_capacity, uint32_t maximum_message,
    uint32_t maximum_bytes, struct virtio_fs_outbox **result)
{
	struct virtio_fs_outbox *outbox;
	int error;

	if (result == NULL || normal_capacity == 0 || priority_capacity == 0 ||
	    maximum_message == 0 ||
	    maximum_message > VIRTIO_FS_BACKEND_MAX_FRAME ||
	    maximum_bytes > VIRTIO_FS_BACKEND_MAX_PENDING_BYTES ||
	    maximum_bytes < maximum_message ||
	    maximum_bytes - maximum_message < maximum_message)
		return (EINVAL);
	*result = NULL;
	outbox = calloc(1, sizeof(*outbox));
	if (outbox == NULL)
		return (ENOMEM);
	error = pthread_mutex_init(&outbox->mutex, NULL);
	if (error != 0) {
		free(outbox);
		return (error);
	}
	outbox->normal.capacity = normal_capacity;
	outbox->priority.capacity = priority_capacity;
	outbox->maximum_message = maximum_message;
	outbox->maximum_bytes = maximum_bytes;
	/*
	 * A full-sized hiprio request remains admissible even when normal
	 * traffic has consumed its entire allowance.
	 */
	outbox->normal_byte_limit = maximum_bytes - maximum_message;
	*result = outbox;
	return (0);
}

void
virtio_fs_outbox_destroy(struct virtio_fs_outbox *outbox)
{

	if (outbox == NULL)
		return;
	virtio_fs_outbox_lane_free(&outbox->priority);
	virtio_fs_outbox_lane_free(&outbox->normal);
	(void)pthread_mutex_destroy(&outbox->mutex);
	free(outbox);
}

int
virtio_fs_outbox_enqueue(struct virtio_fs_outbox *outbox, bool priority,
    const struct virtio_fs_backend_header *header, const void *payload)
{

	return (virtio_fs_outbox_enqueue_on(outbox, priority, 0, header,
	    payload));
}

int
virtio_fs_outbox_enqueue_on(struct virtio_fs_outbox *outbox, bool priority,
    uint32_t queue_id, const struct virtio_fs_backend_header *header,
    const void *payload)
{
	struct virtio_fs_outbox_frame *frame;
	struct virtio_fs_outbox_lane *lane;
	uint8_t wire[VIRTIO_FS_BACKEND_HEADER_SIZE];
	uint64_t total_bytes;
	int error;

	if (outbox == NULL || header == NULL ||
	    (payload == NULL && header->payload_len != 0))
		return (EINVAL);
	error = virtio_fs_backend_header_encode(header, wire);
	if (error != 0)
		return (error);
	if (header->payload_len > outbox->maximum_message)
		return (EMSGSIZE);
	pthread_mutex_lock(&outbox->mutex);
	lane = priority ? &outbox->priority : &outbox->normal;
	total_bytes = outbox->normal.bytes + outbox->priority.bytes;
	if (lane->count == lane->capacity ||
	    header->payload_len > outbox->maximum_bytes - total_bytes ||
	    (!priority && header->payload_len >
	    outbox->normal_byte_limit - outbox->normal.bytes)) {
		error = ENOBUFS;
		goto out;
	}
	frame = malloc(sizeof(*frame) + header->payload_len);
	if (frame == NULL) {
		error = ENOMEM;
		goto out;
	}
	frame->next = NULL;
	frame->header = *header;
	frame->queue_id = queue_id;
	if (header->payload_len != 0)
		memcpy(frame->payload, payload, header->payload_len);
	if (lane->tail == NULL)
		lane->head = frame;
	else
		lane->tail->next = frame;
	lane->tail = frame;
	lane->count++;
	lane->bytes += header->payload_len;
	error = 0;
out:
	pthread_mutex_unlock(&outbox->mutex);
	return (error);
}

int
virtio_fs_outbox_flush_one(struct virtio_fs_outbox *outbox, int fd,
    struct virtio_fs_backend_header *sent_header)
{
	struct virtio_fs_outbox_frame *frame;
	struct virtio_fs_outbox_lane *lane;
	int error;

	if (outbox == NULL || sent_header == NULL)
		return (EINVAL);
	if (virtio_state_ranges_overlap(sent_header, sizeof(*sent_header),
	    outbox, sizeof(*outbox)))
		return (EINVAL);
	pthread_mutex_lock(&outbox->mutex);
	lane = outbox->priority.head != NULL ? &outbox->priority :
	    &outbox->normal;
	frame = lane->head;
	if (frame == NULL) {
		error = ENOENT;
		goto out;
	}
	if (virtio_state_ranges_overlap(sent_header, sizeof(*sent_header),
	    frame, sizeof(*frame) + frame->header.payload_len)) {
		error = EINVAL;
		goto out;
	}
	error = virtio_fs_backend_send_frame(fd, &frame->header,
	    frame->header.payload_len == 0 ? NULL : frame->payload);
	if (error != 0)
		goto out;
	lane->head = frame->next;
	if (lane->head == NULL)
		lane->tail = NULL;
	lane->count--;
	lane->bytes -= frame->header.payload_len;
	*sent_header = frame->header;
	free(frame);
out:
	pthread_mutex_unlock(&outbox->mutex);
	return (error);
}

uint32_t
virtio_fs_outbox_reset(struct virtio_fs_outbox *outbox)
{
	uint32_t count, normal_capacity, priority_capacity;

	if (outbox == NULL)
		return (0);
	pthread_mutex_lock(&outbox->mutex);
	count = outbox->normal.count + outbox->priority.count;
	normal_capacity = outbox->normal.capacity;
	priority_capacity = outbox->priority.capacity;
	virtio_fs_outbox_lane_free(&outbox->priority);
	virtio_fs_outbox_lane_free(&outbox->normal);
	outbox->normal.capacity = normal_capacity;
	outbox->priority.capacity = priority_capacity;
	pthread_mutex_unlock(&outbox->mutex);
	return (count);
}

static uint32_t
virtio_fs_outbox_lane_reset_queue(struct virtio_fs_outbox_lane *lane,
    uint32_t queue_id)
{
	struct virtio_fs_outbox_frame *frame, *next, *previous;
	uint32_t count;

	count = 0;
	previous = NULL;
	for (frame = lane->head; frame != NULL; frame = next) {
		next = frame->next;
		if (frame->queue_id != queue_id) {
			previous = frame;
			continue;
		}
		if (previous == NULL)
			lane->head = next;
		else
			previous->next = next;
		if (lane->tail == frame)
			lane->tail = previous;
		lane->count--;
		lane->bytes -= frame->header.payload_len;
		free(frame);
		count++;
	}
	return (count);
}

uint32_t
virtio_fs_outbox_reset_queue(struct virtio_fs_outbox *outbox,
    uint32_t queue_id)
{
	uint32_t count;

	if (outbox == NULL)
		return (0);
	pthread_mutex_lock(&outbox->mutex);
	count = virtio_fs_outbox_lane_reset_queue(&outbox->priority, queue_id);
	count += virtio_fs_outbox_lane_reset_queue(&outbox->normal, queue_id);
	pthread_mutex_unlock(&outbox->mutex);
	return (count);
}

uint32_t
virtio_fs_outbox_count(struct virtio_fs_outbox *outbox, bool priority)
{
	uint32_t count;

	if (outbox == NULL)
		return (0);
	pthread_mutex_lock(&outbox->mutex);
	count = priority ? outbox->priority.count : outbox->normal.count;
	pthread_mutex_unlock(&outbox->mutex);
	return (count);
}

uint64_t
virtio_fs_outbox_bytes(struct virtio_fs_outbox *outbox)
{
	uint64_t bytes;

	if (outbox == NULL)
		return (0);
	pthread_mutex_lock(&outbox->mutex);
	bytes = outbox->normal.bytes + outbox->priority.bytes;
	pthread_mutex_unlock(&outbox->mutex);
	return (bytes);
}
