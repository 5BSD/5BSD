/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/endian.h>

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "virtio_admin.h"
#include "virtio_admin_capability.h"
#include "virtio_admin_device_parts.h"
#include "virtio_admin_resource.h"
#include "virtio_device_parts_handler.h"
#include "virtio_state_range.h"

#define	VADMIN_DEVICE_PARTS_STATE_MAGIC	0x31535044U	/* "DPS1" */
#define	VADMIN_DEVICE_PARTS_STATE_VERSION	1U
#define	VADMIN_DEVICE_PARTS_STATE_DIGEST_OFFSET	24U

struct vadmin_device_parts_binding {
	struct virtio_admin_device_parts *parts;
	uint16_t opcode;
};

struct virtio_admin_device_parts {
	pthread_mutex_t mutex;
	struct virtio_admin_capability_manager *capabilities;
	struct virtio_admin_resource_manager *resources;
	struct virtio_device_parts_handler *handler;
	_Atomic(uint8_t) driver_limit[2];
	uint8_t device_limit[2];
	bool resource_present[UINT8_MAX];
	uint64_t resource_member[UINT8_MAX];
	struct vadmin_device_parts_binding bindings[8];
	bool commands_registered;
};

static bool
vadmin_device_parts_overlaps_locked(struct virtio_admin_device_parts *parts,
    const void *buffer, size_t length)
{

	return (virtio_state_ranges_overlap(buffer, length, parts,
	    sizeof(*parts)) ||
	    virtio_admin_capability_snapshot_overlaps(parts->capabilities,
	    buffer, length) ||
	    virtio_admin_resource_snapshot_overlaps(parts->resources, buffer,
	    length));
}

static bool
vadmin_device_parts_results_invalid_locked(
    struct virtio_admin_device_parts *parts, const void *input,
    size_t input_length, void *output, size_t capacity, size_t *used)
{

	return (vadmin_device_parts_overlaps_locked(parts, input, input_length) ||
	    vadmin_device_parts_overlaps_locked(parts, output, capacity) ||
	    vadmin_device_parts_overlaps_locked(parts, used, sizeof(*used)) ||
	    virtio_state_ranges_overlap(input, input_length, output, capacity) ||
	    virtio_state_ranges_overlap(input, input_length, used,
	    sizeof(*used)) || virtio_state_ranges_overlap(output, capacity,
	    used, sizeof(*used)));
}

static uint64_t
vadmin_device_parts_digest(const uint8_t *bytes, size_t length)
{
	uint64_t digest;

	digest = UINT64_C(14695981039346656037);
	for (size_t i = 0; i < length; i++) {
		uint8_t byte;

		byte = i >= VADMIN_DEVICE_PARTS_STATE_DIGEST_OFFSET &&
		    i < VADMIN_DEVICE_PARTS_STATE_DIGEST_OFFSET +
		    sizeof(uint64_t) ? 0 : bytes[i];
		digest ^= byte;
		digest *= UINT64_C(1099511628211);
	}
	return (digest);
}

static bool
vadmin_device_parts_match(void *argument, uint64_t flags, const void *data,
    size_t size)
{
	const uint8_t *bytes;

	bytes = data;
	return (flags == 0 &&
	    size == BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_OBJECT_SIZE &&
	    bytes != NULL && bytes[0] == (uint8_t)(uintptr_t)argument);
}

static int
vadmin_device_parts_capability_validate(void *argument,
    const void *device_data, size_t device_size, const void *driver_data,
    size_t driver_size)
{
	struct virtio_admin_device_parts *parts;
	const uint8_t *device, *driver;

	parts = argument;
	device = device_data;
	driver = driver_data;
	if (device_size != 2 || driver_size != 2 || device == NULL ||
	    driver == NULL || device[0] != parts->device_limit[0] ||
	    device[1] != parts->device_limit[1] ||
	    driver[0] > device[0] || driver[1] > device[1])
		return (EINVAL);
	for (uint8_t subtype = 0; subtype < 2; subtype++) {
		uint32_t count, id_limit;
		int error;

		error = virtio_admin_resource_usage(parts->resources,
		    BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_RESOURCE_TYPE,
		    vadmin_device_parts_match, (void *)(uintptr_t)subtype,
		    &count, &id_limit);
		if (error != 0)
			return (error);
		if (count > driver[subtype] || id_limit > driver[subtype])
			return (EBUSY);
	}
	return (0);
}

static void
vadmin_device_parts_capability_apply(void *argument, const void *driver_data,
    size_t driver_size, bool driver_set)
{
	struct virtio_admin_device_parts *parts;
	const uint8_t *driver;

	parts = argument;
	driver = driver_data;
	/*
	 * The capability manager invokes apply only with the immutable
	 * registered size and its owned non-NULL storage.
	 */
	(void)driver_size;
	for (uint8_t subtype = 0; subtype < 2; subtype++)
		atomic_store_explicit(&parts->driver_limit[subtype],
		    driver_set ? driver[subtype] : 0, memory_order_release);
}

static int
vadmin_device_parts_resource_validate(void *argument, uint64_t flags,
    const void *data, size_t size, uint32_t *limit)
{
	struct virtio_admin_device_parts *parts;
	const uint8_t *bytes;

	parts = argument;
	bytes = data;
	if (flags != 0 ||
	    size != BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_OBJECT_SIZE ||
	    bytes == NULL || bytes[0] > BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_SET)
		return (EINVAL);
	for (size_t i = 1; i < size; i++) {
		if (bytes[i] != 0)
			return (EINVAL);
	}
	*limit = atomic_load_explicit(&parts->driver_limit[bytes[0]],
	    memory_order_acquire);
	return (0);
}

int
virtio_admin_device_parts_create(struct virtio_admin_device_parts **result,
    uint8_t get_limit, uint8_t set_limit)
{
	struct virtio_admin_device_parts *parts;
	struct virtio_admin_capability_config capability;
	struct virtio_admin_resource_type resource;
	uint32_t maximum;
	int error;

	if (result == NULL)
		return (EINVAL);
	parts = calloc(1, sizeof(*parts));
	if (parts == NULL)
		return (ENOMEM);
	error = pthread_mutex_init(&parts->mutex, NULL);
	if (error != 0) {
		free(parts);
		return (error);
	}
	parts->device_limit[0] = get_limit;
	parts->device_limit[1] = set_limit;
	error = virtio_admin_resource_manager_create(&parts->resources);
	if (error != 0)
		goto fail;
	maximum = MAX((uint32_t)get_limit, (uint32_t)set_limit);
	resource = (struct virtio_admin_resource_type) {
		.type = BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_RESOURCE_TYPE,
		.limit = MAX(maximum, UINT32_C(1)),
		.minimum_size =
		    BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_OBJECT_SIZE,
		.maximum_size =
		    BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_OBJECT_SIZE,
		.valid_flags = 0,
		.validate = vadmin_device_parts_resource_validate,
		.validate_argument = parts,
	};
	error = virtio_admin_resource_register_type(parts->resources,
	    &resource);
	if (error != 0)
		goto fail;
	error = virtio_admin_capability_manager_create(&parts->capabilities);
	if (error != 0)
		goto fail;
	capability = (struct virtio_admin_capability_config) {
		.id = BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_CAP_ID,
		.device_data = parts->device_limit,
		.size = sizeof(parts->device_limit),
		.validate = vadmin_device_parts_capability_validate,
		.validate_argument = parts,
		.apply = vadmin_device_parts_capability_apply,
		.apply_argument = parts,
	};
	error = virtio_admin_capability_register(parts->capabilities,
	    &capability);
	if (error != 0)
		goto fail;
	*result = parts;
	return (0);

fail:
	virtio_admin_capability_manager_destroy(parts->capabilities);
	virtio_admin_resource_manager_destroy(parts->resources);
	pthread_mutex_destroy(&parts->mutex);
	free(parts);
	return (error);
}

void
virtio_admin_device_parts_reset(struct virtio_admin_device_parts *parts)
{

	if (parts == NULL)
		return;
	pthread_mutex_lock(&parts->mutex);
	/*
	 * Remove objects before publishing zero limits.  Administration queues
	 * are stopped by the caller, so no new operation can interleave.
	 */
	virtio_admin_resource_manager_reset(parts->resources);
	memset(parts->resource_present, 0, sizeof(parts->resource_present));
	memset(parts->resource_member, 0, sizeof(parts->resource_member));
	virtio_admin_capability_manager_reset(parts->capabilities);
	pthread_mutex_unlock(&parts->mutex);
}

void
virtio_admin_device_parts_destroy(struct virtio_admin_device_parts *parts)
{

	if (parts == NULL)
		return;
	virtio_admin_capability_manager_destroy(parts->capabilities);
	virtio_admin_resource_manager_destroy(parts->resources);
	pthread_mutex_destroy(&parts->mutex);
	free(parts);
}

int
virtio_admin_device_parts_set_driver(struct virtio_admin_device_parts *parts,
    const void *data, size_t size)
{
	int error;

	if (parts == NULL)
		return (EINVAL);
	pthread_mutex_lock(&parts->mutex);
	if (vadmin_device_parts_overlaps_locked(parts, data, size))
		error = EINVAL;
	else
		error = virtio_admin_capability_set_driver(parts->capabilities,
		    BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_CAP_ID, data, size);
	pthread_mutex_unlock(&parts->mutex);
	return (error);
}

int
virtio_admin_device_parts_resource_create(
    struct virtio_admin_device_parts *parts, uint32_t id, uint64_t flags,
    const void *data, size_t size)
{

	return (virtio_admin_device_parts_resource_create_for_member(parts, 0,
	    id, flags, data, size));
}

int
virtio_admin_device_parts_resource_create_for_member(
    struct virtio_admin_device_parts *parts, uint64_t member, uint32_t id,
    uint64_t flags, const void *data, size_t size)
{
	int error;

	if (parts == NULL)
		return (EINVAL);
	pthread_mutex_lock(&parts->mutex);
	if (vadmin_device_parts_overlaps_locked(parts, data, size))
		error = EINVAL;
	else
		error = virtio_admin_resource_create(parts->resources,
		    BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_RESOURCE_TYPE, id, flags,
		    data, size);
	if (error == 0) {
		/*
		 * The registered resource limit is at most UINT8_MAX, so every
		 * ID accepted by the generic resource manager indexes these
		 * fixed ownership arrays.
		 */
		parts->resource_member[id] = member;
		parts->resource_present[id] = true;
	}
	pthread_mutex_unlock(&parts->mutex);
	return (error);
}

int
virtio_admin_device_parts_resource_modify(
    struct virtio_admin_device_parts *parts, uint32_t id, const void *data,
    size_t size)
{

	return (virtio_admin_device_parts_resource_modify_for_member(parts, 0,
	    id, data, size));
}

int
virtio_admin_device_parts_resource_modify_for_member(
    struct virtio_admin_device_parts *parts, uint64_t member, uint32_t id,
    const void *data, size_t size)
{
	int error;

	if (parts == NULL)
		return (EINVAL);
	pthread_mutex_lock(&parts->mutex);
	if (vadmin_device_parts_overlaps_locked(parts, data, size))
		error = EINVAL;
	else if (id >= nitems(parts->resource_present) ||
	    !parts->resource_present[id] ||
	    parts->resource_member[id] != member)
		error = ENXIO;
	else
		error = virtio_admin_resource_modify(parts->resources,
		    BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_RESOURCE_TYPE, id, data,
		    size);
	pthread_mutex_unlock(&parts->mutex);
	return (error);
}

int
virtio_admin_device_parts_resource_query(
    struct virtio_admin_device_parts *parts, uint32_t id, uint64_t *flags,
    void *data, size_t capacity, size_t *size)
{

	return (virtio_admin_device_parts_resource_query_for_member(parts, 0,
	    id, flags, data, capacity, size));
}

int
virtio_admin_device_parts_resource_query_for_member(
    struct virtio_admin_device_parts *parts, uint64_t member, uint32_t id,
    uint64_t *flags, void *data, size_t capacity, size_t *size)
{
	int error;

	if (parts == NULL || flags == NULL || size == NULL ||
	    (data == NULL && capacity != 0))
		return (EINVAL);
	pthread_mutex_lock(&parts->mutex);
	if (vadmin_device_parts_results_invalid_locked(parts, NULL, 0, data,
	    capacity, size) ||
	    vadmin_device_parts_overlaps_locked(parts, flags, sizeof(*flags)) ||
	    virtio_state_ranges_overlap(flags, sizeof(*flags), data, capacity) ||
	    virtio_state_ranges_overlap(flags, sizeof(*flags), size,
	    sizeof(*size)))
		error = EINVAL;
	else if (id >= nitems(parts->resource_present) ||
	    !parts->resource_present[id] ||
	    parts->resource_member[id] != member)
		error = ENXIO;
	else
		error = virtio_admin_resource_query(parts->resources,
		    BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_RESOURCE_TYPE, id, flags,
		    data, capacity, size);
	pthread_mutex_unlock(&parts->mutex);
	return (error);
}

int
virtio_admin_device_parts_resource_destroy(
    struct virtio_admin_device_parts *parts, uint32_t id)
{

	return (virtio_admin_device_parts_resource_destroy_for_member(parts, 0,
	    id));
}

int
virtio_admin_device_parts_resource_destroy_for_member(
    struct virtio_admin_device_parts *parts, uint64_t member, uint32_t id)
{
	int error;

	if (parts == NULL)
		return (EINVAL);
	pthread_mutex_lock(&parts->mutex);
	if (id >= nitems(parts->resource_present) ||
	    !parts->resource_present[id] ||
	    parts->resource_member[id] != member)
		error = ENXIO;
	else {
		error = virtio_admin_resource_destroy_object(parts->resources,
		    BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_RESOURCE_TYPE, id);
		if (error == 0) {
			parts->resource_present[id] = false;
			parts->resource_member[id] = 0;
		}
	}
	pthread_mutex_unlock(&parts->mutex);
	return (error);
}

int
virtio_admin_device_parts_resource_member(
    struct virtio_admin_device_parts *parts, uint32_t id, uint64_t *member)
{
	int error;

	if (parts == NULL || member == NULL)
		return (EINVAL);
	pthread_mutex_lock(&parts->mutex);
	if (vadmin_device_parts_overlaps_locked(parts, member,
	    sizeof(*member)))
		error = EINVAL;
	else if (id >= nitems(parts->resource_present) ||
	    !parts->resource_present[id])
		error = ENXIO;
	else {
		*member = parts->resource_member[id];
		error = 0;
	}
	pthread_mutex_unlock(&parts->mutex);
	return (error);
}

int
virtio_admin_device_parts_get_driver(
    struct virtio_admin_device_parts *parts, void *data, size_t capacity,
    size_t *size, bool *driver_set)
{
	int error;

	if (parts == NULL || size == NULL || driver_set == NULL ||
	    (data == NULL && capacity != 0))
		return (EINVAL);
	pthread_mutex_lock(&parts->mutex);
	if (vadmin_device_parts_results_invalid_locked(parts, NULL, 0, data,
	    capacity, size) || vadmin_device_parts_overlaps_locked(parts,
	    driver_set, sizeof(*driver_set)) ||
	    virtio_state_ranges_overlap(data, capacity, driver_set,
	    sizeof(*driver_set)) || virtio_state_ranges_overlap(size,
	    sizeof(*size), driver_set, sizeof(*driver_set)))
		error = EINVAL;
	else
		error = virtio_admin_capability_get_driver(parts->capabilities,
		    BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_CAP_ID, data, capacity,
		    size, driver_set);
	pthread_mutex_unlock(&parts->mutex);
	return (error);
}

int
virtio_admin_device_parts_resource_usage(
    struct virtio_admin_device_parts *parts, uint8_t subtype,
    uint32_t *count, uint32_t *id_limit)
{
	int error;

	if (parts == NULL || count == NULL || id_limit == NULL ||
	    subtype > BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_SET)
		return (EINVAL);
	pthread_mutex_lock(&parts->mutex);
	if (vadmin_device_parts_overlaps_locked(parts, count, sizeof(*count)) ||
	    vadmin_device_parts_overlaps_locked(parts, id_limit,
	    sizeof(*id_limit)) || virtio_state_ranges_overlap(count,
	    sizeof(*count), id_limit, sizeof(*id_limit)))
		error = EINVAL;
	else
		error = virtio_admin_resource_usage(parts->resources,
		    BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_RESOURCE_TYPE,
		    vadmin_device_parts_match, (void *)(uintptr_t)subtype, count,
		    id_limit);
	pthread_mutex_unlock(&parts->mutex);
	return (error);
}

int
virtio_admin_device_parts_bind_handler(
    struct virtio_admin_device_parts *parts,
    struct virtio_device_parts_handler *handler)
{
	int error;

	if (parts == NULL || handler == NULL)
		return (EINVAL);
	pthread_mutex_lock(&parts->mutex);
	if (parts->handler != NULL)
		error = EBUSY;
	else {
		for (uint32_t id = 0; id < nitems(parts->resource_present); id++) {
			if (parts->resource_present[id]) {
				pthread_mutex_unlock(&parts->mutex);
				return (EBUSY);
			}
		}
		parts->handler = handler;
		error = 0;
	}
	pthread_mutex_unlock(&parts->mutex);
	return (error);
}

static int
vadmin_device_parts_authorize_locked(struct virtio_admin_device_parts *parts,
    uint64_t member, uint32_t id, uint8_t subtype)
{
	uint8_t object[BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_OBJECT_SIZE];
	uint64_t flags;
	size_t size;
	int error;

	if (parts->handler == NULL)
		return (ENOTSUP);
	if (id >= nitems(parts->resource_present) ||
	    !parts->resource_present[id] ||
	    parts->resource_member[id] != member)
		return (ENXIO);
	error = virtio_admin_resource_query(parts->resources,
	    BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_RESOURCE_TYPE, id, &flags,
	    object, sizeof(object), &size);
	if (error != 0)
		return (error);
	if (flags != 0 || size != sizeof(object) || object[0] != subtype)
		return (EINVAL);
	return (0);
}

int
virtio_admin_device_parts_metadata(struct virtio_admin_device_parts *parts,
    uint64_t member, uint32_t id, uint8_t type, void *output,
    size_t capacity, size_t *used)
{
	int error;

	if (parts == NULL || used == NULL ||
	    (output == NULL && capacity != 0))
		return (EINVAL);
	pthread_mutex_lock(&parts->mutex);
	if (vadmin_device_parts_results_invalid_locked(parts, NULL, 0, output,
	    capacity, used))
		error = EINVAL;
	else
		error = vadmin_device_parts_authorize_locked(parts, member, id,
		    BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_GET);
	if (error == 0)
		error = virtio_device_parts_handler_metadata(parts->handler,
		    member, type, output, capacity, used);
	pthread_mutex_unlock(&parts->mutex);
	return (error);
}

int
virtio_admin_device_parts_get(struct virtio_admin_device_parts *parts,
    uint64_t member, uint32_t id, uint8_t type, const void *selection,
    size_t selection_size, void *output, size_t capacity, size_t *used)
{
	int error;

	if (parts == NULL || used == NULL ||
	    (selection == NULL && selection_size != 0) ||
	    (output == NULL && capacity != 0))
		return (EINVAL);
	pthread_mutex_lock(&parts->mutex);
	if (vadmin_device_parts_results_invalid_locked(parts, selection,
	    selection_size, output, capacity, used))
		error = EINVAL;
	else
		error = vadmin_device_parts_authorize_locked(parts, member, id,
		    BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_GET);
	if (error == 0)
		error = virtio_device_parts_handler_get(parts->handler, member,
		    type, selection, selection_size, output, capacity, used);
	pthread_mutex_unlock(&parts->mutex);
	return (error);
}

int
virtio_admin_device_parts_set(struct virtio_admin_device_parts *parts,
    uint64_t member, uint32_t id, const void *input, size_t length)
{
	int error;

	if (parts == NULL || input == NULL || length == 0)
		return (EINVAL);
	pthread_mutex_lock(&parts->mutex);
	if (vadmin_device_parts_overlaps_locked(parts, input, length))
		error = EINVAL;
	else
		error = vadmin_device_parts_authorize_locked(parts, member, id,
		    BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_SET);
	if (error == 0)
		error = virtio_device_parts_handler_set(parts->handler, member,
		    input, length);
	pthread_mutex_unlock(&parts->mutex);
	return (error);
}

int
virtio_admin_device_parts_mode_set(struct virtio_admin_device_parts *parts,
    uint64_t member, uint8_t flags)
{
	int error;

	if (parts == NULL)
		return (EINVAL);
	pthread_mutex_lock(&parts->mutex);
	if (parts->handler == NULL)
		error = ENOTSUP;
	else
		error = virtio_device_parts_handler_mode_set(parts->handler,
		    member, flags);
	pthread_mutex_unlock(&parts->mutex);
	return (error);
}

static int
vadmin_device_parts_decode_resource(const void *input, size_t length,
    uint32_t *id)
{
	uint8_t header[BHYVE_VIRTIO_ADMIN_RESOURCE_HEADER_SIZE];

	if (length != 0 && input == NULL)
		return (EINVAL);
	memset(header, 0, sizeof(header));
	if (length != 0)
		memcpy(header, input, MIN(length, sizeof(header)));
	if (le16dec(header) !=
	    BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_RESOURCE_TYPE ||
	    header[2] != 0 || header[3] != 0)
		return (EINVAL);
	*id = le32dec(header + 4);
	return (0);
}

static void
vadmin_device_parts_result_error(struct virtio_admin_command_result *result,
    int error, bool response_too_small)
{

	result->status = response_too_small ?
	    BHYVE_VIRTIO_ADMIN_STATUS_ENOMEM :
	    virtio_admin_status_from_errno(error);
	switch (error) {
	case EINVAL:
		result->qualifier =
		    BHYVE_VIRTIO_ADMIN_QUALIFIER_INVALID_FIELD;
		break;
	case ENOMEM:
	case ENOSPC:
		result->qualifier =
		    BHYVE_VIRTIO_ADMIN_QUALIFIER_NORESOURCE;
		break;
	case EAGAIN:
	case EBUSY:
		result->qualifier =
		    BHYVE_VIRTIO_ADMIN_QUALIFIER_TRYAGAIN;
		break;
	default:
		result->qualifier =
		    BHYVE_VIRTIO_ADMIN_QUALIFIER_INVALID_COMMAND;
		break;
	}
	result->result_length = 0;
}

static bool
vadmin_device_parts_reserved_zero(const uint8_t *bytes, size_t first,
    size_t last)
{

	for (size_t i = first; i < last; i++) {
		if (bytes[i] != 0)
			return (false);
	}
	return (true);
}

static void
vadmin_device_parts_command(void *argument, uint64_t member,
    const void *input, size_t input_length, void *output,
    size_t output_length, struct virtio_admin_command_result *result)
{
	struct vadmin_device_parts_binding *binding;
	struct virtio_admin_device_parts *parts;
	const uint8_t *bytes;
	uint8_t normalized[BHYVE_VIRTIO_ADMIN_RESOURCE_CREATE_HEADER_SIZE +
	    BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_OBJECT_SIZE];
	uint64_t flags;
	uint32_t id;
	size_t used;
	int error;

	binding = argument;
	parts = binding->parts;
	bytes = input;
	memset(normalized, 0, sizeof(normalized));
	if (input_length != 0)
		memcpy(normalized, input, MIN(input_length, sizeof(normalized)));
	used = 0;
	error = vadmin_device_parts_decode_resource(normalized,
	    BHYVE_VIRTIO_ADMIN_RESOURCE_HEADER_SIZE, &id);
	switch (binding->opcode) {
	case BHYVE_VIRTIO_ADMIN_CMD_RESOURCE_OBJ_CREATE:
		if (error == 0) {
			flags = le64dec(normalized +
			    BHYVE_VIRTIO_ADMIN_RESOURCE_HEADER_SIZE);
			error =
			    virtio_admin_device_parts_resource_create_for_member(
			    parts, member, id, flags,
			    normalized +
			    BHYVE_VIRTIO_ADMIN_RESOURCE_CREATE_HEADER_SIZE,
			    BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_OBJECT_SIZE);
		}
		break;
	case BHYVE_VIRTIO_ADMIN_CMD_RESOURCE_OBJ_MODIFY:
		if (error == 0)
			error =
			    virtio_admin_device_parts_resource_modify_for_member(
			    parts, member, id,
			    normalized +
			    BHYVE_VIRTIO_ADMIN_RESOURCE_HEADER_SIZE,
			    BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_OBJECT_SIZE);
		break;
	case BHYVE_VIRTIO_ADMIN_CMD_RESOURCE_OBJ_QUERY:
		if (error == 0)
			error =
			    virtio_admin_device_parts_resource_query_for_member(
			    parts, member, id, &flags, output, output_length,
			    &used);
		if (error == 0)
			result->result_length = used;
		break;
	case BHYVE_VIRTIO_ADMIN_CMD_RESOURCE_OBJ_DESTROY:
		if (error == 0)
			error =
			    virtio_admin_device_parts_resource_destroy_for_member(
			    parts, member, id);
		break;
	case BHYVE_VIRTIO_ADMIN_CMD_DEV_PARTS_METADATA_GET:
		if (error == 0 &&
		    !vadmin_device_parts_reserved_zero(normalized, 9, 16))
			error = EINVAL;
		if (error == 0)
			error = virtio_admin_device_parts_metadata(parts, member,
			    id, normalized[8], output, output_length, &used);
		if (error == 0)
			result->result_length = used;
		break;
	case BHYVE_VIRTIO_ADMIN_CMD_DEV_PARTS_GET:
		if (error == 0 &&
		    !vadmin_device_parts_reserved_zero(normalized, 9, 16))
			error = EINVAL;
		if (error == 0)
			error = virtio_admin_device_parts_get(parts, member, id,
			    normalized[8],
			    input_length > 16 ? bytes + 16 : NULL,
			    input_length > 16 ? input_length - 16 : 0, output,
			    output_length, &used);
		if (error == 0)
			result->result_length = used;
		break;
	case BHYVE_VIRTIO_ADMIN_CMD_DEV_PARTS_SET:
		if (error == 0)
			error = virtio_admin_device_parts_set(parts, member, id,
			    input_length >
			    BHYVE_VIRTIO_ADMIN_RESOURCE_HEADER_SIZE ?
			    bytes + BHYVE_VIRTIO_ADMIN_RESOURCE_HEADER_SIZE :
			    NULL,
			    input_length >
			    BHYVE_VIRTIO_ADMIN_RESOURCE_HEADER_SIZE ?
			    input_length -
			    BHYVE_VIRTIO_ADMIN_RESOURCE_HEADER_SIZE : 0);
		break;
	case BHYVE_VIRTIO_ADMIN_CMD_DEV_MODE_SET:
		/*
		 * DEV_MODE_SET has no resource-object header.  Re-decode the
		 * one-byte command-specific structure and ignore a longer
		 * driver-readable tail as required by section 2.13.1.
		 */
		error = virtio_admin_device_parts_mode_set(parts, member,
		    normalized[0]);
		break;
	default:
		error = EINVAL;
		break;
	}
	if (error != 0)
		vadmin_device_parts_result_error(result, error,
		    binding->opcode ==
		    BHYVE_VIRTIO_ADMIN_CMD_DEV_PARTS_METADATA_GET &&
		    error == ENOSPC);
}

int
virtio_admin_device_parts_register_commands(
    struct virtio_admin_device_parts *parts, struct virtio_admin_owner *owner)
{
	static const uint16_t opcodes[] = {
		BHYVE_VIRTIO_ADMIN_CMD_RESOURCE_OBJ_CREATE,
		BHYVE_VIRTIO_ADMIN_CMD_RESOURCE_OBJ_QUERY,
		BHYVE_VIRTIO_ADMIN_CMD_RESOURCE_OBJ_MODIFY,
		BHYVE_VIRTIO_ADMIN_CMD_RESOURCE_OBJ_DESTROY,
		BHYVE_VIRTIO_ADMIN_CMD_DEV_PARTS_METADATA_GET,
		BHYVE_VIRTIO_ADMIN_CMD_DEV_PARTS_GET,
		BHYVE_VIRTIO_ADMIN_CMD_DEV_PARTS_SET,
		BHYVE_VIRTIO_ADMIN_CMD_DEV_MODE_SET,
	};
	struct virtio_admin_command_registration registrations[nitems(opcodes)];
	int error;

	if (parts == NULL || owner == NULL)
		return (EINVAL);
	pthread_mutex_lock(&parts->mutex);
	if (parts->handler == NULL) {
		pthread_mutex_unlock(&parts->mutex);
		return (ENOTSUP);
	}
	if (parts->commands_registered) {
		pthread_mutex_unlock(&parts->mutex);
		return (EALREADY);
	}
	for (size_t i = 0; i < nitems(opcodes); i++) {
		parts->bindings[i] = (struct vadmin_device_parts_binding) {
			.parts = parts,
			.opcode = opcodes[i],
		};
		registrations[i] =
		    (struct virtio_admin_command_registration) {
			.opcode = opcodes[i],
			.handler = vadmin_device_parts_command,
			.argument = &parts->bindings[i],
		    };
	}
	/*
	 * Keep the composition lock through publication.  Besides making the
	 * binding storage immutable before any owner can invoke it, this makes
	 * concurrent attempts single-winner.  Owner registration does not call
	 * handlers while holding its own mutex.
	 */
	error = virtio_admin_owner_register_commands(owner, registrations,
	    nitems(registrations));
	if (error == 0)
		parts->commands_registered = true;
	pthread_mutex_unlock(&parts->mutex);
	return (error);
}

static int
vadmin_device_parts_state_size_locked(
    struct virtio_admin_device_parts *parts, size_t *result,
    uint32_t *owner_count)
{
	size_t resource_size, total;
	uint32_t count;
	int error;

	error = virtio_admin_resource_snapshot_size(parts->resources,
	    &resource_size);
	if (error != 0)
		return (error);
	count = 0;
	for (uint32_t id = 0; id < nitems(parts->resource_present); id++) {
		if (parts->resource_present[id])
			count++;
	}
	total = BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_STATE_HEADER_SIZE;
	if (resource_size > SIZE_MAX - total)
		return (EOVERFLOW);
	total += resource_size;
	if ((size_t)count > (SIZE_MAX - total) /
	    BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_STATE_MEMBER_SIZE)
		return (EOVERFLOW);
	total += (size_t)count *
	    BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_STATE_MEMBER_SIZE;
	if (total > UINT32_MAX || resource_size > UINT32_MAX)
		return (EOVERFLOW);
	*result = total;
	if (owner_count != NULL)
		*owner_count = count;
	return (0);
}

int
virtio_admin_device_parts_snapshot_size(
    struct virtio_admin_device_parts *parts, size_t *result)
{
	size_t required;
	int error;

	if (parts == NULL || result == NULL)
		return (EINVAL);
	pthread_mutex_lock(&parts->mutex);
	error = vadmin_device_parts_state_size_locked(parts, &required, NULL);
	if (error == 0 && vadmin_device_parts_overlaps_locked(parts, result,
	    sizeof(*result)))
		error = EINVAL;
	if (error == 0)
		*result = required;
	pthread_mutex_unlock(&parts->mutex);
	return (error);
}

int
virtio_admin_device_parts_snapshot(
    struct virtio_admin_device_parts *parts, void *buffer, size_t length)
{
	uint8_t driver[2], *bytes;
	size_t cursor, required, resource_size, driver_size;
	uint32_t object_count, owner_count;
	bool driver_set;
	int error;

	if (parts == NULL || buffer == NULL)
		return (EINVAL);
	bytes = buffer;
	pthread_mutex_lock(&parts->mutex);
	error = vadmin_device_parts_state_size_locked(parts, &required,
	    &owner_count);
	if (error != 0 || length != required) {
		pthread_mutex_unlock(&parts->mutex);
		return (error != 0 ? error : EMSGSIZE);
	}
	if (virtio_state_ranges_overlap(buffer, length, parts,
	    sizeof(*parts)) ||
	    virtio_admin_capability_snapshot_overlaps(parts->capabilities,
	    buffer, length) ||
	    virtio_admin_resource_snapshot_overlaps(parts->resources, buffer,
	    length)) {
		pthread_mutex_unlock(&parts->mutex);
		return (EINVAL);
	}
	error = virtio_admin_resource_count(parts->resources,
	    BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_RESOURCE_TYPE, NULL, NULL,
	    &object_count);
	if (error != 0 || object_count != owner_count) {
		pthread_mutex_unlock(&parts->mutex);
		return (error != 0 ? error : EPROTO);
	}
	error = virtio_admin_capability_get_driver(parts->capabilities,
	    BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_CAP_ID, driver, sizeof(driver),
	    &driver_size, &driver_set);
	if (error != 0 || driver_size != sizeof(driver)) {
		pthread_mutex_unlock(&parts->mutex);
		return (error != 0 ? error : EPROTO);
	}
	resource_size = required -
	    BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_STATE_HEADER_SIZE -
	    (size_t)owner_count *
	    BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_STATE_MEMBER_SIZE;
	memset(bytes, 0, length);
	le32enc(bytes, VADMIN_DEVICE_PARTS_STATE_MAGIC);
	le16enc(bytes + 4, VADMIN_DEVICE_PARTS_STATE_VERSION);
	le16enc(bytes + 6,
	    BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_STATE_HEADER_SIZE);
	le32enc(bytes + 8, (uint32_t)length);
	le32enc(bytes + 16, (uint32_t)resource_size);
	le32enc(bytes + 20, owner_count);
	bytes[32] = driver_set ? 1 : 0;
	if (driver_set) {
		bytes[33] = driver[0];
		bytes[34] = driver[1];
	}
	cursor = BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_STATE_HEADER_SIZE;
	error = virtio_admin_resource_snapshot(parts->resources,
	    bytes + cursor, resource_size);
	if (error != 0) {
		pthread_mutex_unlock(&parts->mutex);
		return (error);
	}
	cursor += resource_size;
	for (uint32_t id = 0; id < nitems(parts->resource_present); id++) {
		if (!parts->resource_present[id])
			continue;
		le32enc(bytes + cursor, id);
		le64enc(bytes + cursor + 8, parts->resource_member[id]);
		cursor +=
		    BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_STATE_MEMBER_SIZE;
	}
	le64enc(bytes + VADMIN_DEVICE_PARTS_STATE_DIGEST_OFFSET,
	    vadmin_device_parts_digest(bytes, length));
	pthread_mutex_unlock(&parts->mutex);
	return (0);
}

int
virtio_admin_device_parts_restore(
    struct virtio_admin_device_parts *parts, const void *buffer, size_t length)
{
	struct virtio_admin_resource_restore_stage *stage;
	bool present[UINT8_MAX];
	uint64_t members[UINT8_MAX];
	const uint8_t *bytes;
	size_t cursor, expected, resource_size;
	uint32_t object_count, owner_count, prior_id;
	uint8_t old_limit[2], target_limit[2];
	bool driver_set;
	int error;

	if (parts == NULL || buffer == NULL)
		return (EINVAL);
	if (length < BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_STATE_HEADER_SIZE ||
	    length > UINT32_MAX)
		return (EMSGSIZE);
	if (virtio_state_ranges_overlap(buffer, length, parts,
	    sizeof(*parts)) ||
	    virtio_admin_capability_snapshot_overlaps(parts->capabilities,
	    buffer, length) ||
	    virtio_admin_resource_snapshot_overlaps(parts->resources, buffer,
	    length))
		return (EINVAL);
	bytes = buffer;
	if (le32dec(bytes) != VADMIN_DEVICE_PARTS_STATE_MAGIC ||
	    le16dec(bytes + 4) != VADMIN_DEVICE_PARTS_STATE_VERSION ||
	    le16dec(bytes + 6) !=
	    BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_STATE_HEADER_SIZE ||
	    le32dec(bytes + 8) != length || le32dec(bytes + 12) != 0 ||
	    le64dec(bytes + VADMIN_DEVICE_PARTS_STATE_DIGEST_OFFSET) !=
	    vadmin_device_parts_digest(bytes, length))
		return (EPROTO);
	resource_size = le32dec(bytes + 16);
	owner_count = le32dec(bytes + 20);
	if (resource_size <
	    BHYVE_VIRTIO_ADMIN_RESOURCE_STATE_HEADER_SIZE ||
	    owner_count > nitems(present) || bytes[32] > 1)
		return (EPROTO);
	for (size_t i = 35;
	    i < BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_STATE_HEADER_SIZE; i++) {
		if (bytes[i] != 0)
			return (EPROTO);
	}
	driver_set = bytes[32] != 0;
	target_limit[0] = bytes[33];
	target_limit[1] = bytes[34];
	if ((!driver_set &&
	    (target_limit[0] != 0 || target_limit[1] != 0)) ||
	    target_limit[0] > parts->device_limit[0] ||
	    target_limit[1] > parts->device_limit[1])
		return (ENOTSUP);
	expected = BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_STATE_HEADER_SIZE;
	if (resource_size > SIZE_MAX - expected)
		return (EOVERFLOW);
	expected += resource_size;
	if ((size_t)owner_count > (SIZE_MAX - expected) /
	    BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_STATE_MEMBER_SIZE)
		return (EOVERFLOW);
	expected += (size_t)owner_count *
	    BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_STATE_MEMBER_SIZE;
	if (expected != length)
		return (EPROTO);

	memset(present, 0, sizeof(present));
	memset(members, 0, sizeof(members));
	cursor = BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_STATE_HEADER_SIZE +
	    resource_size;
	prior_id = 0;
	for (uint32_t entry = 0; entry < owner_count; entry++) {
		uint32_t id;

		id = le32dec(bytes + cursor);
		if (le32dec(bytes + cursor + 4) != 0 ||
		    id >= nitems(present) || present[id] ||
		    (entry != 0 && id <= prior_id))
			return (EPROTO);
		present[id] = true;
		members[id] = le64dec(bytes + cursor + 8);
		prior_id = id;
		cursor +=
		    BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_STATE_MEMBER_SIZE;
	}

	pthread_mutex_lock(&parts->mutex);
	for (uint8_t subtype = 0; subtype < 2; subtype++) {
		old_limit[subtype] = atomic_load_explicit(
		    &parts->driver_limit[subtype], memory_order_acquire);
		atomic_store_explicit(&parts->driver_limit[subtype],
		    target_limit[subtype], memory_order_release);
	}
	error = virtio_admin_resource_restore_prepare(parts->resources,
	    bytes + BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_STATE_HEADER_SIZE,
	    resource_size, &stage);
	for (uint8_t subtype = 0; subtype < 2; subtype++)
		atomic_store_explicit(&parts->driver_limit[subtype],
		    old_limit[subtype], memory_order_release);
	if (error != 0)
		goto out;
	error = virtio_admin_resource_restore_stage_count(stage,
	    BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_RESOURCE_TYPE, NULL, NULL,
	    &object_count);
	if (error != 0 || object_count != owner_count) {
		error = error != 0 ? error : EPROTO;
		goto discard;
	}
	for (uint32_t id = 0; id < nitems(present); id++) {
		uint8_t object[BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_OBJECT_SIZE];
		uint64_t flags;
		size_t object_size;

		error = virtio_admin_resource_restore_stage_query(stage,
		    BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_RESOURCE_TYPE, id, &flags,
		    object, sizeof(object), &object_size);
		if (present[id] && error != 0)
			goto discard;
		if (!present[id] && error == 0) {
			error = EPROTO;
			goto discard;
		}
		if (!present[id] && error == ENOENT) {
			error = 0;
			continue;
		}
		if (error != 0)
			goto discard;
	}
	error = virtio_admin_resource_restore_commit(parts->resources, stage);
	if (error != 0)
		goto discard;
	if (driver_set) {
		/*
		 * Resource preparation above validated every staged object
		 * against target_limit.  Commit cannot allocate, and this exact
		 * capability publication cannot allocate either.  Holding the
		 * composition lock keeps that preflight valid.
		 */
		error = virtio_admin_capability_set_driver_exact(
		    parts->capabilities,
		    BHYVE_VIRTIO_ADMIN_DEVICE_PARTS_CAP_ID, target_limit,
		    sizeof(target_limit));
	} else {
		virtio_admin_capability_manager_reset(parts->capabilities);
	}
	if (error == 0) {
		memcpy(parts->resource_present, present, sizeof(present));
		memcpy(parts->resource_member, members, sizeof(members));
	}
discard:
	virtio_admin_resource_restore_stage_destroy(stage);
out:
	pthread_mutex_unlock(&parts->mutex);
	return (error);
}
