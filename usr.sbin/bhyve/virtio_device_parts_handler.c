/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/endian.h>

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "virtio_device_parts.h"
#include "virtio_device_parts_handler.h"
#include "virtio_state_range.h"

struct virtio_device_parts_handler {
	pthread_mutex_t mutex;
	struct virtio_device_parts_handler_config config;
};

struct vdev_parts_request {
	uint64_t selector;
	uint32_t length;
	uint16_t type;
	uint8_t flags;
	bool exists;
	bool returned;
};

static bool
vdev_parts_handler_overlaps(struct virtio_device_parts_handler *handler,
    const void *buffer, size_t length)
{

	return (virtio_state_ranges_overlap(buffer, length, handler,
	    sizeof(*handler)));
}

static bool
vdev_parts_handler_results_invalid(
    struct virtio_device_parts_handler *handler, const void *input,
    size_t input_length, void *output, size_t capacity, size_t *used)
{

	return (vdev_parts_handler_overlaps(handler, input, input_length) ||
	    vdev_parts_handler_overlaps(handler, output, capacity) ||
	    vdev_parts_handler_overlaps(handler, used, sizeof(*used)) ||
	    virtio_state_ranges_overlap(input, input_length, output, capacity) ||
	    virtio_state_ranges_overlap(input, input_length, used,
	    sizeof(*used)) || virtio_state_ranges_overlap(output, capacity,
	    used, sizeof(*used)));
}

static int
vdev_parts_validate_headers(const void *buffer, size_t length,
    uint32_t maximum_count, bool independent, uint32_t *count)
{
	struct virtio_device_parts_iterator iterator;
	struct virtio_device_part part;
	const uint8_t *bytes;
	uint32_t seen;
	int error;

	if (buffer == NULL && length != 0)
		return (EINVAL);
	if (independent && length % BHYVE_VIRTIO_DEV_PART_HEADER_SIZE != 0)
		return (EPROTO);
	if (length == 0) {
		if (count != NULL)
			*count = 0;
		return (0);
	}
	bytes = buffer;
	virtio_device_part_headers_iterator_init(&iterator, buffer, length);
	seen = 0;
	for (;;) {
		if (independent)
			virtio_device_part_selection_iterator_init(&iterator,
			    bytes + (size_t)seen *
			    BHYVE_VIRTIO_DEV_PART_HEADER_SIZE,
			    BHYVE_VIRTIO_DEV_PART_HEADER_SIZE);
		error = virtio_device_parts_next(&iterator, &part);
		if (error != 0)
			break;
		if (seen == maximum_count)
			return (EOVERFLOW);
		seen++;
		if (independent &&
		    virtio_device_parts_next(&iterator, &part) != ENOENT)
			return (EPROTO);
		if (independent &&
		    (size_t)seen * BHYVE_VIRTIO_DEV_PART_HEADER_SIZE == length) {
			error = ENOENT;
			break;
		}
	}
	if (error != ENOENT)
		return (error);
	if (count != NULL)
		*count = seen;
	return (0);
}

static int
vdev_parts_request_compare(const void *left_arg, const void *right_arg)
{
	const struct vdev_parts_request *left, *right;

	left = left_arg;
	right = right_arg;
	if (left->type != right->type)
		return (left->type < right->type ? -1 : 1);
	if (left->selector != right->selector)
		return (left->selector < right->selector ? -1 : 1);
	return (0);
}

static struct vdev_parts_request *
vdev_parts_request_find(struct vdev_parts_request *requests, uint32_t count,
    const struct virtio_device_part *part)
{
	struct vdev_parts_request key;
	struct vdev_parts_request *request;

	memset(&key, 0, sizeof(key));
	key.type = part->type;
	key.flags = part->flags;
	key.selector = part->selector;
	key.length = part->length;
	request = bsearch(&key, requests, count, sizeof(*requests),
	    vdev_parts_request_compare);
	if (request == NULL || request->flags != part->flags ||
	    request->length != part->length)
		return (NULL);
	return (request);
}

static int
vdev_parts_request_load(const void *selection, uint32_t count,
    struct vdev_parts_request *requests, uint32_t *known_count)
{
	struct virtio_device_parts_iterator iterator;
	struct virtio_device_part part;
	const uint8_t *bytes;
	uint32_t known;
	int error;

	bytes = selection;
	known = 0;
	for (uint32_t i = 0; i < count; i++) {
		virtio_device_part_selection_iterator_init(&iterator,
		    bytes + (size_t)i * BHYVE_VIRTIO_DEV_PART_HEADER_SIZE,
		    BHYVE_VIRTIO_DEV_PART_HEADER_SIZE);
		error = virtio_device_parts_next(&iterator, &part);
		if (error != 0)
			return (error);
		if (part.type < BHYVE_VIRTIO_DEV_PART_DEV_FEATURES ||
		    part.type > BHYVE_VIRTIO_DEV_PART_VQ_NOTIFY_CFG)
			continue;
		requests[known].type = part.type;
		requests[known].flags = part.flags;
		requests[known].selector = part.selector;
		requests[known].length = part.length;
		known++;
	}
	qsort(requests, known, sizeof(*requests), vdev_parts_request_compare);
	for (uint32_t i = 1; i < known; i++) {
		if (vdev_parts_request_compare(&requests[i - 1],
		    &requests[i]) == 0)
			return (EPROTO);
	}
	*known_count = known;
	return (0);
}

static int
vdev_parts_request_mark(struct vdev_parts_request *requests, uint32_t count,
    const void *buffer, size_t length)
{
	struct virtio_device_parts_iterator iterator;
	struct vdev_parts_request *request;
	struct virtio_device_part part;
	int error;

	if (count == 0)
		return (0);
	virtio_device_part_headers_iterator_init(&iterator, buffer, length);
	while ((error = virtio_device_parts_next(&iterator, &part)) == 0) {
		request = vdev_parts_request_find(requests, count, &part);
		if (request != NULL)
			request->exists = true;
	}
	return (error == ENOENT ? 0 : error);
}

static int
vdev_parts_selected_output(struct vdev_parts_request *requests, uint32_t count,
    const void *buffer, size_t length)
{
	struct virtio_device_parts_iterator iterator;
	struct vdev_parts_request *request;
	struct virtio_device_part part;
	uint32_t predecessor_types, part_bit;
	int error;

	predecessor_types = 0;
	for (uint32_t i = 0; i < count; i++) {
		if (!requests[i].exists)
			continue;
		part_bit = UINT32_C(1) <<
		    (requests[i].type - BHYVE_VIRTIO_DEV_PART_DEV_FEATURES);
		predecessor_types |= part_bit - 1;
	}
	virtio_device_parts_iterator_init(&iterator, buffer, length);
	while ((error = virtio_device_parts_next(&iterator, &part)) == 0) {
		if (part.type < BHYVE_VIRTIO_DEV_PART_DEV_FEATURES ||
		    part.type > BHYVE_VIRTIO_DEV_PART_VQ_NOTIFY_CFG)
			return (EPROTO);
		request = vdev_parts_request_find(requests, count, &part);
		part_bit = UINT32_C(1) <<
		    (part.type - BHYVE_VIRTIO_DEV_PART_DEV_FEATURES);
		if (request == NULL &&
		    (predecessor_types & part_bit) == 0)
			return (EPROTO);
		if (request != NULL)
			request->returned = true;
	}
	return (error == ENOENT ? 0 : error);
}

static int
vdev_parts_validate_values(const void *buffer, size_t length,
    uint32_t maximum_count)
{
	struct virtio_device_parts_iterator iterator;
	struct virtio_device_part part;
	uint32_t seen;
	int error;

	virtio_device_parts_iterator_init(&iterator, buffer, length);
	seen = 0;
	while ((error = virtio_device_parts_next(&iterator, &part)) == 0) {
		if (seen == maximum_count)
			return (EOVERFLOW);
		seen++;
	}
	return (error == ENOENT ? 0 : error);
}

int
virtio_device_parts_handler_create(
    struct virtio_device_parts_handler **result,
    const struct virtio_device_parts_handler_config *config)
{
	struct virtio_device_parts_handler *handler;
	int error;

	if (result == NULL || config == NULL ||
	    virtio_state_ranges_overlap(result, sizeof(*result), config,
	    sizeof(*config)) ||
	    config->ops.schema == NULL || config->ops.capture == NULL ||
	    config->ops.mode_get == NULL || config->ops.mode_set == NULL ||
	    config->ops.prepare_restore == NULL ||
	    config->ops.commit_restore == NULL ||
	    config->ops.discard_restore == NULL ||
	    config->maximum_parts_size == 0 ||
	    config->maximum_parts_size >
	    BHYVE_VIRTIO_DEVICE_PARTS_MAX_SIZE ||
	    config->maximum_part_count == 0 ||
	    config->maximum_part_count >
	    config->maximum_parts_size /
	    BHYVE_VIRTIO_DEV_PART_HEADER_SIZE)
		return (EINVAL);
	handler = calloc(1, sizeof(*handler));
	if (handler == NULL)
		return (ENOMEM);
	error = pthread_mutex_init(&handler->mutex, NULL);
	if (error != 0) {
		free(handler);
		return (error);
	}
	handler->config = *config;
	*result = handler;
	return (0);
}

void
virtio_device_parts_handler_destroy(
    struct virtio_device_parts_handler *handler)
{

	if (handler == NULL)
		return;
	pthread_mutex_destroy(&handler->mutex);
	free(handler);
}

int
virtio_device_parts_handler_metadata(
    struct virtio_device_parts_handler *handler, uint64_t member, uint8_t type,
    void *output, size_t capacity, size_t *used)
{
	uint8_t *headers, *bytes;
	size_t header_capacity, header_size, required;
	uint32_t count;
	int error;

	if (handler == NULL || (output == NULL && capacity != 0) ||
	    used == NULL)
		return (EINVAL);
	if (vdev_parts_handler_results_invalid(handler, NULL, 0, output,
	    capacity, used))
		return (EINVAL);
	if (type > BHYVE_VIRTIO_DEVICE_PARTS_METADATA_LIST)
		return (EINVAL);
	header_capacity = (size_t)handler->config.maximum_part_count *
	    BHYVE_VIRTIO_DEV_PART_HEADER_SIZE;
	headers = malloc(header_capacity);
	if (headers == NULL)
		return (ENOMEM);
	pthread_mutex_lock(&handler->mutex);
	error = handler->config.ops.schema(handler->config.argument, member,
	    headers, header_capacity, &header_size);
	if (error != 0)
		goto out;
	if (header_size > header_capacity) {
		error = EOVERFLOW;
		goto out;
	}
	error = vdev_parts_validate_headers(headers, header_size,
	    handler->config.maximum_part_count, false, &count);
	if (error != 0)
		goto out;
	required = type == BHYVE_VIRTIO_DEVICE_PARTS_METADATA_LIST ?
	    sizeof(uint64_t) + header_size : sizeof(uint64_t);
	if (capacity < required) {
		error = ENOSPC;
		goto out;
	}
	bytes = output;
	memset(bytes, 0, required);
	if (type == BHYVE_VIRTIO_DEVICE_PARTS_METADATA_SIZE)
		le32enc(bytes, handler->config.maximum_parts_size);
	else
		le32enc(bytes, count);
	if (type == BHYVE_VIRTIO_DEVICE_PARTS_METADATA_LIST &&
	    header_size != 0)
		memcpy(bytes + sizeof(uint64_t), headers, header_size);
	*used = required;
	error = 0;
out:
	pthread_mutex_unlock(&handler->mutex);
	free(headers);
	return (error);
}

int
virtio_device_parts_handler_get(
    struct virtio_device_parts_handler *handler, uint64_t member, uint8_t type,
    const void *selection, size_t selection_size, void *output,
    size_t capacity, size_t *used)
{
	struct vdev_parts_request *requests;
	uint8_t *captured, *schema;
	size_t captured_size, copied, schema_capacity, schema_size;
	uint32_t selection_count, request_count;
	int error;

	if (handler == NULL || (output == NULL && capacity != 0) ||
	    used == NULL ||
	    (selection == NULL && selection_size != 0) ||
	    type > BHYVE_VIRTIO_DEVICE_PARTS_GET_ALL ||
	    (type == BHYVE_VIRTIO_DEVICE_PARTS_GET_ALL &&
	    selection_size != 0))
		return (EINVAL);
	if (vdev_parts_handler_results_invalid(handler, selection,
	    selection_size, output, capacity, used))
		return (EINVAL);
	requests = NULL;
	schema = NULL;
	captured = malloc(handler->config.maximum_parts_size);
	if (captured == NULL)
		return (ENOMEM);
	request_count = 0;
	if (type == BHYVE_VIRTIO_DEVICE_PARTS_GET_SELECTED) {
		error = vdev_parts_validate_headers(selection, selection_size,
		    handler->config.maximum_part_count, true, &selection_count);
		if (error != 0) {
			free(captured);
			return (error);
		}
		if (selection_count != 0) {
			requests = calloc(selection_count, sizeof(*requests));
			if (requests == NULL) {
				free(captured);
				return (ENOMEM);
			}
			error = vdev_parts_request_load(selection, selection_count,
			    requests, &request_count);
			if (error != 0) {
				free(requests);
				free(captured);
				return (error);
			}
		}
		schema_capacity =
		    (size_t)handler->config.maximum_part_count *
		    BHYVE_VIRTIO_DEV_PART_HEADER_SIZE;
		schema = malloc(schema_capacity);
		if (schema == NULL) {
			free(requests);
			free(captured);
			return (ENOMEM);
		}
	}
	pthread_mutex_lock(&handler->mutex);
	if (type == BHYVE_VIRTIO_DEVICE_PARTS_GET_SELECTED) {
		error = handler->config.ops.schema(handler->config.argument,
		    member, schema, schema_capacity, &schema_size);
		if (error != 0)
			goto out;
		if (schema_size > schema_capacity) {
			error = EOVERFLOW;
			goto out;
		}
		error = vdev_parts_validate_headers(schema, schema_size,
		    handler->config.maximum_part_count, false, NULL);
		if (error != 0)
			goto out;
		error = vdev_parts_request_mark(requests, request_count, schema,
		    schema_size);
		if (error != 0)
			goto out;
	}
	error = handler->config.ops.capture(handler->config.argument, member,
	    type, selection, selection_size, captured,
	    handler->config.maximum_parts_size, &captured_size);
	if (error == 0) {
		if (captured_size > handler->config.maximum_parts_size)
			error = EOVERFLOW;
		else
			error = vdev_parts_validate_values(captured, captured_size,
			    handler->config.maximum_part_count);
	}
	if (error == 0 &&
	    type == BHYVE_VIRTIO_DEVICE_PARTS_GET_SELECTED) {
		error = vdev_parts_selected_output(requests, request_count,
		    captured, captured_size);
		if (error == 0) {
			for (uint32_t i = 0; i < request_count; i++) {
				if (requests[i].exists && !requests[i].returned) {
					error = EPROTO;
					break;
				}
			}
		}
	}
out:
	pthread_mutex_unlock(&handler->mutex);
	if (error == 0) {
		copied = capacity < captured_size ? capacity : captured_size;
		if (copied != 0)
			memcpy(output, captured, copied);
		*used = captured_size;
	}
	free(schema);
	free(requests);
	free(captured);
	return (error);
}

int
virtio_device_parts_handler_set(
    struct virtio_device_parts_handler *handler, uint64_t member,
    const void *input, size_t length)
{
	void *transaction;
	bool stopped;
	int error;

	if (handler == NULL || input == NULL || length == 0 ||
	    length > handler->config.maximum_parts_size)
		return (EINVAL);
	if (vdev_parts_handler_overlaps(handler, input, length))
		return (EINVAL);
	error = vdev_parts_validate_values(input, length,
	    handler->config.maximum_part_count);
	if (error != 0)
		return (error);
	pthread_mutex_lock(&handler->mutex);
	error = handler->config.ops.mode_get(handler->config.argument, member,
	    &stopped);
	if (error != 0)
		goto out;
	if (!stopped) {
		error = EBUSY;
		goto out;
	}
	transaction = NULL;
	error = handler->config.ops.prepare_restore(handler->config.argument,
	    member, input, length, &transaction);
	if (error == 0)
		handler->config.ops.commit_restore(handler->config.argument,
		    member, transaction);
	handler->config.ops.discard_restore(handler->config.argument, member,
	    transaction);
out:
	pthread_mutex_unlock(&handler->mutex);
	return (error);
}

int
virtio_device_parts_handler_mode_set(
    struct virtio_device_parts_handler *handler, uint64_t member,
    uint8_t flags)
{
	int error;

	if (handler == NULL ||
	    (flags & ~BHYVE_VIRTIO_DEVICE_MODE_STOPPED) != 0)
		return (EINVAL);
	pthread_mutex_lock(&handler->mutex);
	error = handler->config.ops.mode_set(handler->config.argument, member,
	    (flags & BHYVE_VIRTIO_DEVICE_MODE_STOPPED) != 0);
	pthread_mutex_unlock(&handler->mutex);
	return (error);
}
