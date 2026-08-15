/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/endian.h>
#include <sys/param.h>

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "virtio_admin.h"
#include "virtio_admin_resource.h"
#include "virtio_state_range.h"

#define	VADMIN_RESOURCE_STATE_MAGIC	0x31534f52U	/* "ROS1" */
#define	VADMIN_RESOURCE_STATE_VERSION	1U
#define	VADMIN_RESOURCE_STATE_DIGEST_OFFSET	24U

struct vadmin_resource_key {
	uint16_t type;
	uint32_t id;
};

struct vadmin_resource_object {
	uint8_t *data;
	size_t size;
	uint64_t flags;
	uint64_t sequence;
	struct vadmin_resource_key dependencies[
	    BHYVE_VIRTIO_ADMIN_RESOURCE_MAX_DEPENDENCIES];
	uint8_t dependency_count;
	bool present;
};

struct vadmin_resource_type {
	struct virtio_admin_resource_type config;
	struct vadmin_resource_object *objects;
};

struct vadmin_resource_binding {
	struct virtio_admin_resource_manager *manager;
	uint16_t opcode;
};

struct virtio_admin_resource_manager {
	pthread_mutex_t mutex;
	struct vadmin_resource_type types[
	    BHYVE_VIRTIO_ADMIN_RESOURCE_MAX_TYPES];
	struct vadmin_resource_binding bindings[4];
	uint64_t next_sequence;
	uint64_t generation;
	uint8_t type_count;
	bool commands_registered;
};

struct virtio_admin_resource_restore_stage {
	struct vadmin_resource_type types[
	    BHYVE_VIRTIO_ADMIN_RESOURCE_MAX_TYPES];
	uint64_t next_sequence;
	uint64_t source_generation;
	uint8_t type_count;
	bool committed;
};

static bool vadmin_resource_snapshot_overlaps_locked(
    struct virtio_admin_resource_manager *, const void *, size_t);

static bool
vadmin_resource_object_bytes(uint32_t limit, size_t *result)
{

	return (!__builtin_mul_overflow((size_t)limit,
	    sizeof(struct vadmin_resource_object), result));
}

static bool
vadmin_resource_results_invalid_locked(
    struct virtio_admin_resource_manager *manager, uint64_t *flags,
    void *data, size_t capacity, size_t *size)
{

	return (vadmin_resource_snapshot_overlaps_locked(manager, flags,
	    sizeof(*flags)) || vadmin_resource_snapshot_overlaps_locked(manager,
	    data, capacity) || vadmin_resource_snapshot_overlaps_locked(manager,
	    size, sizeof(*size)) ||
	    virtio_state_ranges_overlap(flags, sizeof(*flags), data, capacity) ||
	    virtio_state_ranges_overlap(flags, sizeof(*flags), size,
	    sizeof(*size)) || virtio_state_ranges_overlap(data, capacity, size,
	    sizeof(*size)));
}

static bool
vadmin_resource_stage_overlaps(
    struct virtio_admin_resource_restore_stage *stage, const void *buffer,
    size_t length)
{

	if (virtio_state_ranges_overlap(buffer, length, stage, sizeof(*stage)))
		return (true);
	for (uint8_t type_index = 0; type_index < stage->type_count;
	    type_index++) {
		struct vadmin_resource_type *resource_type;
		size_t object_bytes;

		resource_type = &stage->types[type_index];
		if (!vadmin_resource_object_bytes(resource_type->config.limit,
		    &object_bytes) ||
		    virtio_state_ranges_overlap(buffer, length,
		    resource_type->objects, object_bytes))
			return (true);
		for (uint32_t id = 0; id < resource_type->config.limit; id++) {
			struct vadmin_resource_object *object;

			object = &resource_type->objects[id];
			if (object->present && virtio_state_ranges_overlap(buffer,
			    length, object->data, object->size))
				return (true);
		}
	}
	return (false);
}

static struct vadmin_resource_type *
vadmin_resource_find_type(struct virtio_admin_resource_manager *manager,
    uint16_t type)
{

	for (uint8_t i = 0; i < manager->type_count; i++) {
		if (manager->types[i].config.type == type)
			return (&manager->types[i]);
	}
	return (NULL);
}

static struct vadmin_resource_object *
vadmin_resource_find_object(struct virtio_admin_resource_manager *manager,
    uint16_t type, uint32_t id)
{
	struct vadmin_resource_type *resource_type;

	resource_type = vadmin_resource_find_type(manager, type);
	if (resource_type == NULL || id >= resource_type->config.limit ||
	    !resource_type->objects[id].present)
		return (NULL);
	return (&resource_type->objects[id]);
}

static int
vadmin_resource_validate(struct vadmin_resource_type *resource_type,
    uint32_t id, uint64_t flags, const void *data, size_t size)
{
	uint32_t limit;
	int error;

	if (id >= resource_type->config.limit ||
	    size < resource_type->config.minimum_size ||
	    size > resource_type->config.maximum_size ||
	    (flags & ~resource_type->config.valid_flags) != 0)
		return (EINVAL);
	if (resource_type->config.validate == NULL)
		return (0);
	limit = resource_type->config.limit;
	error = resource_type->config.validate(
	    resource_type->config.validate_argument, flags, data, size, &limit);
	if (error != 0)
		return (error);
	if (limit > resource_type->config.limit || id >= limit)
		return (EINVAL);
	return (0);
}

static size_t
vadmin_resource_align(size_t value)
{

	return ((value + sizeof(uint64_t) - 1) &
	    ~(sizeof(uint64_t) - 1));
}

static uint64_t
vadmin_resource_digest(const uint8_t *bytes, size_t length)
{
	uint64_t digest;

	digest = UINT64_C(14695981039346656037);
	for (size_t i = 0; i < length; i++) {
		uint8_t byte;

		byte = i >= VADMIN_RESOURCE_STATE_DIGEST_OFFSET &&
		    i < VADMIN_RESOURCE_STATE_DIGEST_OFFSET + sizeof(uint64_t) ?
		    0 : bytes[i];
		digest ^= byte;
		digest *= UINT64_C(1099511628211);
	}
	return (digest);
}

static bool
vadmin_resource_has_dependents(struct virtio_admin_resource_manager *manager,
    uint16_t type, uint32_t id)
{
	struct vadmin_resource_object *object;

	for (uint8_t type_index = 0; type_index < manager->type_count;
	    type_index++) {
		struct vadmin_resource_type *resource_type;

		resource_type = &manager->types[type_index];
		for (uint32_t object_id = 0;
		    object_id < resource_type->config.limit; object_id++) {
			object = &resource_type->objects[object_id];
			if (!object->present)
				continue;
			for (uint8_t dependency = 0;
			    dependency < object->dependency_count; dependency++) {
				if (object->dependencies[dependency].type == type &&
				    object->dependencies[dependency].id == id)
					return (true);
			}
		}
	}
	return (false);
}

int
virtio_admin_resource_manager_create(
    struct virtio_admin_resource_manager **result)
{
	struct virtio_admin_resource_manager *manager;
	int error;

	if (result == NULL)
		return (EINVAL);
	manager = calloc(1, sizeof(*manager));
	if (manager == NULL)
		return (ENOMEM);
	error = pthread_mutex_init(&manager->mutex, NULL);
	if (error != 0) {
		free(manager);
		return (error);
	}
	manager->next_sequence = 1;
	*result = manager;
	return (0);
}

void
virtio_admin_resource_manager_reset(
    struct virtio_admin_resource_manager *manager)
{

	if (manager == NULL)
		return;
	pthread_mutex_lock(&manager->mutex);
	for (uint8_t type_index = 0; type_index < manager->type_count;
	    type_index++) {
		struct vadmin_resource_type *resource_type;

		resource_type = &manager->types[type_index];
		for (uint32_t id = 0; id < resource_type->config.limit; id++) {
			free(resource_type->objects[id].data);
			memset(&resource_type->objects[id], 0,
			    sizeof(resource_type->objects[id]));
		}
	}
	manager->next_sequence = 1;
	manager->generation++;
	pthread_mutex_unlock(&manager->mutex);
}

void
virtio_admin_resource_manager_destroy(
    struct virtio_admin_resource_manager *manager)
{

	if (manager == NULL)
		return;
	virtio_admin_resource_manager_reset(manager);
	for (uint8_t i = 0; i < manager->type_count; i++)
		free(manager->types[i].objects);
	pthread_mutex_destroy(&manager->mutex);
	free(manager);
}

int
virtio_admin_resource_register_type(
    struct virtio_admin_resource_manager *manager,
    const struct virtio_admin_resource_type *config)
{
	struct vadmin_resource_object *objects;
	struct vadmin_resource_type *resource_type;
	int error;

	if (manager == NULL || config == NULL)
		return (EINVAL);
	pthread_mutex_lock(&manager->mutex);
	error = vadmin_resource_snapshot_overlaps_locked(manager, config,
	    sizeof(*config));
	pthread_mutex_unlock(&manager->mutex);
	if (error)
		return (EINVAL);
	if (config->limit == 0 ||
	    config->maximum_size > BHYVE_VIRTIO_ADMIN_RESOURCE_MAX_OBJECT_SIZE ||
	    config->minimum_size > config->maximum_size)
		return (EINVAL);
	objects = calloc(config->limit, sizeof(*objects));
	if (objects == NULL)
		return (ENOMEM);
	pthread_mutex_lock(&manager->mutex);
	if (manager->commands_registered) {
		error = EBUSY;
	} else if (manager->type_count >= BHYVE_VIRTIO_ADMIN_RESOURCE_MAX_TYPES) {
		error = ENOSPC;
	} else if (vadmin_resource_find_type(manager, config->type) != NULL) {
		error = EEXIST;
	} else {
		resource_type = &manager->types[manager->type_count++];
		resource_type->config = *config;
		resource_type->objects = objects;
		objects = NULL;
		manager->generation++;
		error = 0;
	}
	pthread_mutex_unlock(&manager->mutex);
	free(objects);
	return (error);
}

int
virtio_admin_resource_create(struct virtio_admin_resource_manager *manager,
    uint16_t type, uint32_t id, uint64_t flags, const void *data, size_t size)
{
	struct vadmin_resource_object *object;
	struct vadmin_resource_type *resource_type;
	uint8_t *copy;
	int error;

	if (manager == NULL || size >
	    BHYVE_VIRTIO_ADMIN_RESOURCE_MAX_OBJECT_SIZE ||
	    (size != 0 && data == NULL))
		return (EINVAL);
	pthread_mutex_lock(&manager->mutex);
	error = vadmin_resource_snapshot_overlaps_locked(manager, data, size);
	pthread_mutex_unlock(&manager->mutex);
	if (error)
		return (EINVAL);
	copy = size == 0 ? NULL : malloc(size);
	if (size != 0 && copy == NULL)
		return (ENOMEM);
	if (size != 0)
		memcpy(copy, data, size);
	pthread_mutex_lock(&manager->mutex);
	resource_type = vadmin_resource_find_type(manager, type);
	/*
	 * Validate the private candidate that will be published, not the caller's
	 * buffer.  The copy is this operation's ownership boundary: validation
	 * must never approve bytes other than the ones retained by the manager.
	 */
	error = resource_type == NULL ? EINVAL :
	    vadmin_resource_validate(resource_type, id, flags, copy, size);
	if (error == 0) {
		object = &resource_type->objects[id];
		if (object->present) {
			error = EEXIST;
		} else if (manager->next_sequence == UINT64_MAX) {
			error = ENOSPC;
		} else {
			*object = (struct vadmin_resource_object) {
				.data = copy,
				.size = size,
				.flags = flags,
				.sequence = manager->next_sequence++,
				.present = true,
			};
			manager->generation++;
			copy = NULL;
			error = 0;
		}
	}
	pthread_mutex_unlock(&manager->mutex);
	free(copy);
	return (error);
}

int
virtio_admin_resource_modify(struct virtio_admin_resource_manager *manager,
    uint16_t type, uint32_t id, const void *data, size_t size)
{
	struct vadmin_resource_object *object;
	struct vadmin_resource_type *resource_type;
	uint8_t *copy, *old;
	int error;

	if (manager == NULL || size >
	    BHYVE_VIRTIO_ADMIN_RESOURCE_MAX_OBJECT_SIZE ||
	    (size != 0 && data == NULL))
		return (EINVAL);
	pthread_mutex_lock(&manager->mutex);
	error = vadmin_resource_snapshot_overlaps_locked(manager, data, size);
	pthread_mutex_unlock(&manager->mutex);
	if (error)
		return (EINVAL);
	copy = size == 0 ? NULL : malloc(size);
	if (size != 0 && copy == NULL)
		return (ENOMEM);
	if (size != 0)
		memcpy(copy, data, size);
	old = NULL;
	pthread_mutex_lock(&manager->mutex);
	resource_type = vadmin_resource_find_type(manager, type);
	object = vadmin_resource_find_object(manager, type, id);
	if (resource_type == NULL)
		error = EINVAL;
	else if (object == NULL)
		error = ENXIO;
	else
		error = vadmin_resource_validate(resource_type, id, object->flags,
		    copy, size);
	if (error == 0 && vadmin_resource_has_dependents(manager, type, id))
		error = EBUSY;
	if (error == 0) {
		old = object->data;
		object->data = copy;
		object->size = size;
		manager->generation++;
		copy = NULL;
		error = 0;
	}
	pthread_mutex_unlock(&manager->mutex);
	free(old);
	free(copy);
	return (error);
}

int
virtio_admin_resource_query(struct virtio_admin_resource_manager *manager,
    uint16_t type, uint32_t id, uint64_t *flags, void *data, size_t capacity,
    size_t *size)
{
	struct vadmin_resource_object *object;
	size_t copied;

	if (manager == NULL || flags == NULL || size == NULL ||
	    (capacity != 0 && data == NULL))
		return (EINVAL);
	pthread_mutex_lock(&manager->mutex);
	if (vadmin_resource_results_invalid_locked(manager, flags, data,
	    capacity, size)) {
		pthread_mutex_unlock(&manager->mutex);
		return (EINVAL);
	}
	object = vadmin_resource_find_object(manager, type, id);
	if (object == NULL) {
		pthread_mutex_unlock(&manager->mutex);
		return (ENXIO);
	}
	*flags = object->flags;
	*size = object->size;
	copied = MIN(capacity, object->size);
	if (copied != 0)
		memcpy(data, object->data, copied);
	pthread_mutex_unlock(&manager->mutex);
	return (0);
}

int
virtio_admin_resource_destroy_object(
    struct virtio_admin_resource_manager *manager, uint16_t type, uint32_t id)
{
	struct vadmin_resource_object *object;
	uint8_t *data;
	int error;

	if (manager == NULL)
		return (EINVAL);
	data = NULL;
	pthread_mutex_lock(&manager->mutex);
	object = vadmin_resource_find_object(manager, type, id);
	if (object == NULL) {
		error = ENXIO;
	} else if (vadmin_resource_has_dependents(manager, type, id)) {
		error = EBUSY;
	} else {
		data = object->data;
		memset(object, 0, sizeof(*object));
		manager->generation++;
		error = 0;
	}
	pthread_mutex_unlock(&manager->mutex);
	free(data);
	return (error);
}

int
virtio_admin_resource_count(struct virtio_admin_resource_manager *manager,
    uint16_t type, virtio_admin_resource_match_cb match, void *argument,
    uint32_t *result)
{
	uint32_t id_limit;

	return (virtio_admin_resource_usage(manager, type, match, argument,
	    result, &id_limit));
}

int
virtio_admin_resource_usage(struct virtio_admin_resource_manager *manager,
    uint16_t type, virtio_admin_resource_match_cb match, void *argument,
    uint32_t *result, uint32_t *id_limit)
{
	struct vadmin_resource_type *resource_type;
	uint32_t count, high;

	if (manager == NULL || result == NULL || id_limit == NULL)
		return (EINVAL);
	pthread_mutex_lock(&manager->mutex);
	if (vadmin_resource_snapshot_overlaps_locked(manager, result,
	    sizeof(*result)) || vadmin_resource_snapshot_overlaps_locked(manager,
	    id_limit, sizeof(*id_limit)) || virtio_state_ranges_overlap(result,
	    sizeof(*result), id_limit, sizeof(*id_limit))) {
		pthread_mutex_unlock(&manager->mutex);
		return (EINVAL);
	}
	resource_type = vadmin_resource_find_type(manager, type);
	if (resource_type == NULL) {
		pthread_mutex_unlock(&manager->mutex);
		return (ENXIO);
	}
	count = 0;
	high = 0;
	for (uint32_t id = 0; id < resource_type->config.limit; id++) {
		struct vadmin_resource_object *object;

		object = &resource_type->objects[id];
		if (object->present && (match == NULL ||
		    match(argument, object->flags, object->data,
		    object->size))) {
			count++;
			high = id + 1;
		}
	}
	*result = count;
	*id_limit = high;
	pthread_mutex_unlock(&manager->mutex);
	return (0);
}

int
virtio_admin_resource_add_dependency(
    struct virtio_admin_resource_manager *manager, uint16_t dependent_type,
    uint32_t dependent_id, uint16_t required_type, uint32_t required_id)
{
	struct vadmin_resource_object *dependent, *required;
	int error;

	if (manager == NULL || dependent_type == required_type)
		return (EINVAL);
	pthread_mutex_lock(&manager->mutex);
	dependent = vadmin_resource_find_object(manager, dependent_type,
	    dependent_id);
	required = vadmin_resource_find_object(manager, required_type,
	    required_id);
	if (dependent == NULL || required == NULL) {
		error = ENXIO;
	} else if (required->sequence >= dependent->sequence) {
		error = EINVAL;
	} else {
		error = 0;
		for (uint8_t i = 0; i < dependent->dependency_count; i++) {
			if (dependent->dependencies[i].type == required_type &&
			    dependent->dependencies[i].id == required_id) {
				error = EEXIST;
				break;
			}
		}
		if (error == 0 && dependent->dependency_count >=
		    BHYVE_VIRTIO_ADMIN_RESOURCE_MAX_DEPENDENCIES)
			error = ENOSPC;
		if (error == 0) {
			dependent->dependencies[dependent->dependency_count++] =
			    (struct vadmin_resource_key) {
				.type = required_type,
				.id = required_id,
			    };
			manager->generation++;
		}
	}
	pthread_mutex_unlock(&manager->mutex);
	return (error);
}

static int
vadmin_resource_decode_header(const void *input, size_t input_length,
    uint16_t *type, uint32_t *id)
{
	uint8_t header[BHYVE_VIRTIO_ADMIN_RESOURCE_HEADER_SIZE];

	if (input_length != 0 && input == NULL)
		return (EINVAL);
	memset(header, 0, sizeof(header));
	if (input_length != 0)
		memcpy(header, input, MIN(input_length, sizeof(header)));
	if (header[2] != 0 || header[3] != 0)
		return (EINVAL);
	*type = le16dec(header);
	*id = le32dec(header + 4);
	return (0);
}

static int
vadmin_resource_normalize_object(struct virtio_admin_resource_manager *manager,
    uint16_t type, const uint8_t *input, size_t input_length, uint8_t **storage,
    const void **object, size_t *object_length)
{
	struct vadmin_resource_type *resource_type;
	size_t maximum_size, minimum_size;

	*storage = NULL;
	*object = NULL;
	*object_length = 0;
	pthread_mutex_lock(&manager->mutex);
	resource_type = vadmin_resource_find_type(manager, type);
	if (resource_type == NULL) {
		pthread_mutex_unlock(&manager->mutex);
		return (ENXIO);
	}
	minimum_size = resource_type->config.minimum_size;
	maximum_size = resource_type->config.maximum_size;
	pthread_mutex_unlock(&manager->mutex);

	/*
	 * VirtIO 1.4 section 2.13.1 makes command structures extensible in
	 * both directions.  Preserve a variable-size object when it is within
	 * its advertised bounds, zero-extend it to the minimum expected
	 * structure, and ignore bytes beyond the maximum expected structure.
	 */
	*object_length = MIN(MAX(input_length, minimum_size), maximum_size);
	if (*object_length == 0)
		return (0);
	*storage = calloc(1, *object_length);
	if (*storage == NULL)
		return (ENOMEM);
	if (input_length != 0)
		memcpy(*storage, input, MIN(input_length, *object_length));
	*object = *storage;
	return (0);
}

static void
vadmin_resource_command(void *argument, uint64_t member_id, const void *input,
    size_t input_length, void *output, size_t output_length,
    struct virtio_admin_command_result *result)
{
	struct vadmin_resource_binding *binding;
	struct virtio_admin_resource_manager *manager;
	const uint8_t *bytes;
	const void *object;
	uint8_t create_header[BHYVE_VIRTIO_ADMIN_RESOURCE_CREATE_HEADER_SIZE];
	uint8_t *object_storage;
	uint64_t flags;
	uint32_t id;
	uint16_t type;
	size_t object_input_length, object_size;
	int error;

	binding = argument;
	manager = binding->manager;
	bytes = input;
	object_storage = NULL;
	if (member_id != 0) {
		result->status = BHYVE_VIRTIO_ADMIN_STATUS_EINVAL;
		result->qualifier =
		    BHYVE_VIRTIO_ADMIN_QUALIFIER_INVALID_MEMBER;
		result->result_length = 0;
		return;
	}
	error = vadmin_resource_decode_header(bytes, input_length, &type, &id);
	if (error != 0)
		goto done;
	switch (binding->opcode) {
	case BHYVE_VIRTIO_ADMIN_CMD_RESOURCE_OBJ_CREATE:
		memset(create_header, 0, sizeof(create_header));
		if (input_length != 0)
			memcpy(create_header, bytes,
			    MIN(input_length, sizeof(create_header)));
		flags = le64dec(create_header +
		    BHYVE_VIRTIO_ADMIN_RESOURCE_HEADER_SIZE);
		object_input_length = input_length >
		    BHYVE_VIRTIO_ADMIN_RESOURCE_CREATE_HEADER_SIZE ?
		    input_length -
		    BHYVE_VIRTIO_ADMIN_RESOURCE_CREATE_HEADER_SIZE : 0;
		error = vadmin_resource_normalize_object(manager, type,
		    object_input_length == 0 ? NULL :
		    bytes + BHYVE_VIRTIO_ADMIN_RESOURCE_CREATE_HEADER_SIZE,
		    object_input_length, &object_storage, &object, &object_size);
		if (error != 0)
			break;
		error = virtio_admin_resource_create(manager, type, id, flags,
		    object, object_size);
		break;
	case BHYVE_VIRTIO_ADMIN_CMD_RESOURCE_OBJ_MODIFY:
		object_input_length = input_length >
		    BHYVE_VIRTIO_ADMIN_RESOURCE_HEADER_SIZE ?
		    input_length - BHYVE_VIRTIO_ADMIN_RESOURCE_HEADER_SIZE : 0;
		error = vadmin_resource_normalize_object(manager, type,
		    object_input_length == 0 ? NULL :
		    bytes + BHYVE_VIRTIO_ADMIN_RESOURCE_HEADER_SIZE,
		    object_input_length, &object_storage, &object, &object_size);
		if (error != 0)
			break;
		error = virtio_admin_resource_modify(manager, type, id,
		    object, object_size);
		break;
	case BHYVE_VIRTIO_ADMIN_CMD_RESOURCE_OBJ_QUERY:
		error = virtio_admin_resource_query(manager, type, id, &flags,
		    output, output_length, &object_size);
		if (error == 0)
			result->result_length = object_size;
		break;
	case BHYVE_VIRTIO_ADMIN_CMD_RESOURCE_OBJ_DESTROY:
		error = virtio_admin_resource_destroy_object(manager, type, id);
		break;
	default:
		error = EINVAL;
		break;
	}
done:
	free(object_storage);
	if (error != 0) {
		result->status = virtio_admin_status_from_errno(error);
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
}

int
virtio_admin_resource_register_commands(
    struct virtio_admin_resource_manager *manager,
    struct virtio_admin_owner *owner)
{
	static const uint16_t opcodes[] = {
		BHYVE_VIRTIO_ADMIN_CMD_RESOURCE_OBJ_CREATE,
		BHYVE_VIRTIO_ADMIN_CMD_RESOURCE_OBJ_MODIFY,
		BHYVE_VIRTIO_ADMIN_CMD_RESOURCE_OBJ_QUERY,
		BHYVE_VIRTIO_ADMIN_CMD_RESOURCE_OBJ_DESTROY,
	};
	struct virtio_admin_command_registration registrations[nitems(opcodes)];
	int error;

	if (manager == NULL || owner == NULL)
		return (EINVAL);
	pthread_mutex_lock(&manager->mutex);
	if (manager->commands_registered) {
		pthread_mutex_unlock(&manager->mutex);
		return (EALREADY);
	}
	for (size_t i = 0; i < nitems(opcodes); i++) {
		manager->bindings[i] = (struct vadmin_resource_binding) {
			.manager = manager,
			.opcode = opcodes[i],
		};
		registrations[i] =
		    (struct virtio_admin_command_registration) {
			.opcode = opcodes[i],
			.handler = vadmin_resource_command,
			.argument = &manager->bindings[i],
		    };
	}
	error = virtio_admin_owner_register_commands(owner, registrations,
	    nitems(registrations));
	if (error == 0)
		manager->commands_registered = true;
	pthread_mutex_unlock(&manager->mutex);
	return (error);
}

static int
vadmin_resource_state_size_locked(
    struct virtio_admin_resource_manager *manager, size_t *result,
    uint32_t *object_count)
{
	size_t total;
	uint32_t count;

	total = BHYVE_VIRTIO_ADMIN_RESOURCE_STATE_HEADER_SIZE;
	count = 0;
	for (uint8_t type_index = 0; type_index < manager->type_count;
	    type_index++) {
		struct vadmin_resource_type *resource_type;

		resource_type = &manager->types[type_index];
		for (uint32_t id = 0; id < resource_type->config.limit; id++) {
			struct vadmin_resource_object *object;
			size_t entry_size;

			object = &resource_type->objects[id];
			if (!object->present)
				continue;
			entry_size =
			    BHYVE_VIRTIO_ADMIN_RESOURCE_STATE_ENTRY_SIZE +
			    (size_t)object->dependency_count * 8;
			if (object->size > SIZE_MAX - entry_size)
				return (EOVERFLOW);
			entry_size += object->size;
			if (entry_size > SIZE_MAX - (sizeof(uint64_t) - 1))
				return (EOVERFLOW);
			entry_size = vadmin_resource_align(entry_size);
			if (entry_size > SIZE_MAX - total || count == UINT32_MAX)
				return (EOVERFLOW);
			total += entry_size;
			if (total > UINT32_MAX)
				return (EOVERFLOW);
			count++;
		}
	}
	*result = total;
	if (object_count != NULL)
		*object_count = count;
	return (0);
}

int
virtio_admin_resource_snapshot_size(
    struct virtio_admin_resource_manager *manager, size_t *result)
{
	size_t required;
	int error;

	if (manager == NULL || result == NULL)
		return (EINVAL);
	pthread_mutex_lock(&manager->mutex);
	error = vadmin_resource_state_size_locked(manager, &required, NULL);
	if (error == 0 && vadmin_resource_snapshot_overlaps_locked(manager,
	    result, sizeof(*result)))
		error = EINVAL;
	if (error == 0)
		*result = required;
	pthread_mutex_unlock(&manager->mutex);
	return (error);
}

static bool
vadmin_resource_snapshot_overlaps_locked(
    struct virtio_admin_resource_manager *manager, const void *buffer,
    size_t length)
{
	struct vadmin_resource_object *object;
	struct vadmin_resource_type *resource_type;

	if (virtio_state_ranges_overlap(buffer, length, manager,
	    sizeof(*manager)))
		return (true);
	for (uint8_t type_index = 0; type_index < manager->type_count;
	    type_index++) {
		size_t object_bytes;

		resource_type = &manager->types[type_index];
		if (!vadmin_resource_object_bytes(resource_type->config.limit,
		    &object_bytes))
			return (true);
		if (virtio_state_ranges_overlap(buffer, length,
		    resource_type->objects, object_bytes))
			return (true);
		for (uint32_t id = 0; id < resource_type->config.limit; id++) {
			object = &resource_type->objects[id];
			if (object->present &&
			    virtio_state_ranges_overlap(buffer, length,
			    object->data, object->size))
				return (true);
		}
	}
	return (false);
}

bool
virtio_admin_resource_snapshot_overlaps(
    struct virtio_admin_resource_manager *manager, const void *buffer,
    size_t length)
{
	bool overlaps;

	if (manager == NULL)
		return (false);
	pthread_mutex_lock(&manager->mutex);
	overlaps = vadmin_resource_snapshot_overlaps_locked(manager, buffer,
	    length);
	pthread_mutex_unlock(&manager->mutex);
	return (overlaps);
}

int
virtio_admin_resource_snapshot(struct virtio_admin_resource_manager *manager,
    void *buffer, size_t length)
{
	struct vadmin_resource_object *object;
	struct vadmin_resource_type *resource_type;
	uint8_t *bytes;
	size_t required, cursor;
	uint32_t object_count;
	int error;

	if (manager == NULL || buffer == NULL)
		return (EINVAL);
	bytes = buffer;
	pthread_mutex_lock(&manager->mutex);
	error = vadmin_resource_state_size_locked(manager, &required,
	    &object_count);
	if (error != 0 || length != required) {
		pthread_mutex_unlock(&manager->mutex);
		return (error != 0 ? error : EMSGSIZE);
	}
	if (vadmin_resource_snapshot_overlaps_locked(manager, buffer,
	    length)) {
		pthread_mutex_unlock(&manager->mutex);
		return (EINVAL);
	}
	memset(bytes, 0, length);
	le32enc(bytes, VADMIN_RESOURCE_STATE_MAGIC);
	le16enc(bytes + 4, VADMIN_RESOURCE_STATE_VERSION);
	le16enc(bytes + 6,
	    BHYVE_VIRTIO_ADMIN_RESOURCE_STATE_HEADER_SIZE);
	le32enc(bytes + 8, (uint32_t)length);
	le32enc(bytes + 12, object_count);
	le64enc(bytes + 16, manager->next_sequence);
	cursor = BHYVE_VIRTIO_ADMIN_RESOURCE_STATE_HEADER_SIZE;
	for (uint8_t type_index = 0; type_index < manager->type_count;
	    type_index++) {
		resource_type = &manager->types[type_index];
		for (uint32_t id = 0; id < resource_type->config.limit; id++) {
			object = &resource_type->objects[id];
			if (!object->present)
				continue;
			le16enc(bytes + cursor, resource_type->config.type);
			bytes[cursor + 2] = object->dependency_count;
			le32enc(bytes + cursor + 4, id);
			le64enc(bytes + cursor + 8, object->flags);
			le64enc(bytes + cursor + 16, object->sequence);
			le32enc(bytes + cursor + 24, (uint32_t)object->size);
			cursor +=
			    BHYVE_VIRTIO_ADMIN_RESOURCE_STATE_ENTRY_SIZE;
			for (uint8_t dependency = 0;
			    dependency < object->dependency_count; dependency++) {
				le16enc(bytes + cursor,
				    object->dependencies[dependency].type);
				le32enc(bytes + cursor + 4,
				    object->dependencies[dependency].id);
				cursor += 8;
			}
			if (object->size != 0) {
				memcpy(bytes + cursor, object->data,
				    object->size);
				cursor += object->size;
			}
			cursor = vadmin_resource_align(cursor);
		}
	}
	le64enc(bytes + VADMIN_RESOURCE_STATE_DIGEST_OFFSET,
	    vadmin_resource_digest(bytes, length));
	pthread_mutex_unlock(&manager->mutex);
	return (0);
}

static void
vadmin_resource_free_staged(struct vadmin_resource_type *types,
    uint8_t type_count)
{

	for (uint8_t type_index = 0; type_index < type_count; type_index++) {
		if (types[type_index].objects == NULL)
			continue;
		for (uint32_t id = 0; id < types[type_index].config.limit; id++)
			free(types[type_index].objects[id].data);
		free(types[type_index].objects);
		types[type_index].objects = NULL;
	}
}

static struct vadmin_resource_type *
vadmin_resource_find_staged_type(struct vadmin_resource_type *types,
    uint8_t type_count, uint16_t type)
{

	for (uint8_t i = 0; i < type_count; i++) {
		if (types[i].config.type == type)
			return (&types[i]);
	}
	return (NULL);
}

int
virtio_admin_resource_restore_prepare(
    struct virtio_admin_resource_manager *manager, const void *buffer,
    size_t length, struct virtio_admin_resource_restore_stage **result)
{
	struct virtio_admin_resource_restore_stage *stage;
	const uint8_t *bytes;
	size_t cursor;
	uint64_t next_sequence;
	uint32_t object_count;
	int error;

	if (manager == NULL || buffer == NULL || result == NULL)
		return (EINVAL);
	if (virtio_admin_resource_snapshot_overlaps(manager, result,
	    sizeof(*result)) || virtio_state_ranges_overlap(buffer, length,
	    result, sizeof(*result)))
		return (EINVAL);
	if (length < BHYVE_VIRTIO_ADMIN_RESOURCE_STATE_HEADER_SIZE ||
	    length > UINT32_MAX)
		return (EMSGSIZE);
	if (virtio_admin_resource_snapshot_overlaps(manager, buffer, length))
		return (EINVAL);
	bytes = buffer;
	if (le32dec(bytes) != VADMIN_RESOURCE_STATE_MAGIC ||
	    le16dec(bytes + 4) != VADMIN_RESOURCE_STATE_VERSION ||
	    le16dec(bytes + 6) !=
	    BHYVE_VIRTIO_ADMIN_RESOURCE_STATE_HEADER_SIZE ||
	    le32dec(bytes + 8) != length ||
	    le64dec(bytes + VADMIN_RESOURCE_STATE_DIGEST_OFFSET) !=
	    vadmin_resource_digest(bytes, length))
		return (EPROTO);
	object_count = le32dec(bytes + 12);
	next_sequence = le64dec(bytes + 16);
	if (next_sequence == 0 || object_count >
	    (length - BHYVE_VIRTIO_ADMIN_RESOURCE_STATE_HEADER_SIZE) /
	    BHYVE_VIRTIO_ADMIN_RESOURCE_STATE_ENTRY_SIZE)
		return (EPROTO);

	stage = calloc(1, sizeof(*stage));
	if (stage == NULL)
		return (ENOMEM);
	pthread_mutex_lock(&manager->mutex);
	stage->source_generation = manager->generation;
	stage->type_count = manager->type_count;
	for (uint8_t i = 0; i < manager->type_count; i++) {
		stage->types[i].config = manager->types[i].config;
		stage->types[i].objects = calloc(stage->types[i].config.limit,
		    sizeof(*stage->types[i].objects));
		if (stage->types[i].objects == NULL) {
			error = ENOMEM;
			goto fail;
		}
	}
	cursor = BHYVE_VIRTIO_ADMIN_RESOURCE_STATE_HEADER_SIZE;
	for (uint32_t entry = 0; entry < object_count; entry++) {
		struct vadmin_resource_object *object;
		struct vadmin_resource_type *resource_type;
		size_t dependency_bytes, entry_end;
		uint64_t flags, sequence;
		uint32_t id, object_size;
		uint16_t type;
		uint8_t dependency_count;

		if (cursor > length || length - cursor <
		    BHYVE_VIRTIO_ADMIN_RESOURCE_STATE_ENTRY_SIZE) {
			error = EPROTO;
			goto fail;
		}
		type = le16dec(bytes + cursor);
		dependency_count = bytes[cursor + 2];
		id = le32dec(bytes + cursor + 4);
		flags = le64dec(bytes + cursor + 8);
		sequence = le64dec(bytes + cursor + 16);
		object_size = le32dec(bytes + cursor + 24);
		if (bytes[cursor + 3] != 0 ||
		    le32dec(bytes + cursor + 28) != 0 ||
		    dependency_count >
		    BHYVE_VIRTIO_ADMIN_RESOURCE_MAX_DEPENDENCIES ||
		    sequence == 0 || sequence >= next_sequence) {
			error = EPROTO;
			goto fail;
		}
		resource_type = vadmin_resource_find_staged_type(stage->types,
		    stage->type_count, type);
		if (resource_type == NULL ||
		    id >= resource_type->config.limit) {
			error = ENOTSUP;
			goto fail;
		}
		object = &resource_type->objects[id];
		if (object->present) {
			error = EPROTO;
			goto fail;
		}
		dependency_bytes = (size_t)dependency_count * 8;
		if (object_size > SIZE_MAX -
		    BHYVE_VIRTIO_ADMIN_RESOURCE_STATE_ENTRY_SIZE -
		    dependency_bytes) {
			error = EOVERFLOW;
			goto fail;
		}
		entry_end =
		    BHYVE_VIRTIO_ADMIN_RESOURCE_STATE_ENTRY_SIZE +
		    dependency_bytes + object_size;
		if (entry_end > length - cursor) {
			error = EPROTO;
			goto fail;
		}
		entry_end += cursor;
		if (vadmin_resource_validate(resource_type, id, flags,
		    bytes + cursor +
		    BHYVE_VIRTIO_ADMIN_RESOURCE_STATE_ENTRY_SIZE +
		    dependency_bytes, object_size) != 0) {
			error = ENOTSUP;
			goto fail;
		}
		*object = (struct vadmin_resource_object) {
			.size = object_size,
			.flags = flags,
			.sequence = sequence,
			.dependency_count = dependency_count,
			.present = true,
		};
		cursor += BHYVE_VIRTIO_ADMIN_RESOURCE_STATE_ENTRY_SIZE;
		for (uint8_t dependency = 0;
		    dependency < dependency_count; dependency++) {
			if (le16dec(bytes + cursor + 2) != 0) {
				error = EPROTO;
				goto fail;
			}
			object->dependencies[dependency] =
			    (struct vadmin_resource_key) {
				.type = le16dec(bytes + cursor),
				.id = le32dec(bytes + cursor + 4),
			    };
			cursor += 8;
		}
		if (object_size != 0) {
			object->data = malloc(object_size);
			if (object->data == NULL) {
				error = ENOMEM;
				goto fail;
			}
			memcpy(object->data, bytes + cursor, object_size);
			cursor += object_size;
		}
		if (cursor > SIZE_MAX - (sizeof(uint64_t) - 1)) {
			error = EOVERFLOW;
			goto fail;
		}
		entry_end = vadmin_resource_align(cursor);
		if (entry_end > length) {
			error = EPROTO;
			goto fail;
		}
		while (cursor < entry_end) {
			if (bytes[cursor++] != 0) {
				error = EPROTO;
				goto fail;
			}
		}
	}
	if (cursor != length) {
		error = EPROTO;
		goto fail;
	}
	for (uint8_t type_index = 0; type_index < stage->type_count;
	    type_index++) {
		struct vadmin_resource_type *resource_type;

		resource_type = &stage->types[type_index];
		for (uint32_t id = 0; id < resource_type->config.limit; id++) {
			struct vadmin_resource_object *object;

			object = &resource_type->objects[id];
			if (!object->present)
				continue;
			for (uint8_t dependency = 0;
			    dependency < object->dependency_count; dependency++) {
				struct vadmin_resource_object *required;

				required = NULL;
				if (object->dependencies[dependency].type !=
				    resource_type->config.type) {
					struct vadmin_resource_type *required_type;

					required_type =
					    vadmin_resource_find_staged_type(
					    stage->types, stage->type_count,
					    object->dependencies[dependency].type);
					if (required_type != NULL &&
					    object->dependencies[dependency].id <
					    required_type->config.limit)
						required = &required_type->objects[
						    object->dependencies[
						    dependency].id];
				}
				if (required == NULL || !required->present ||
				    required->sequence >= object->sequence) {
					error = EPROTO;
					goto fail;
				}
				for (uint8_t earlier = 0;
				    earlier < dependency; earlier++) {
					if (object->dependencies[earlier].type ==
					    object->dependencies[dependency].type &&
					    object->dependencies[earlier].id ==
					    object->dependencies[dependency].id) {
						error = EPROTO;
						goto fail;
					}
				}
			}
		}
	}
	stage->next_sequence = next_sequence;
	error = 0;
fail:
	pthread_mutex_unlock(&manager->mutex);
	if (error != 0) {
		vadmin_resource_free_staged(stage->types, stage->type_count);
		free(stage);
	} else
		*result = stage;
	return (error);
}

int
virtio_admin_resource_restore_commit(
    struct virtio_admin_resource_manager *manager,
    struct virtio_admin_resource_restore_stage *stage)
{
	int error;

	if (manager == NULL || stage == NULL)
		return (EINVAL);
	pthread_mutex_lock(&manager->mutex);
	if (stage->committed) {
		error = EALREADY;
		goto out;
	}
	if (stage->source_generation != manager->generation) {
		error = EBUSY;
		goto out;
	}
	if (stage->type_count != manager->type_count) {
		error = ENOTSUP;
		goto out;
	}
	for (uint8_t i = 0; i < manager->type_count; i++) {
		const struct virtio_admin_resource_type *current, *prepared;

		current = &manager->types[i].config;
		prepared = &stage->types[i].config;
		if (current->type != prepared->type ||
		    current->limit != prepared->limit ||
		    current->minimum_size != prepared->minimum_size ||
		    current->maximum_size != prepared->maximum_size ||
		    current->valid_flags != prepared->valid_flags) {
			error = ENOTSUP;
			goto out;
		}
	}
	for (uint8_t i = 0; i < manager->type_count; i++) {
		struct vadmin_resource_object *old;

		old = manager->types[i].objects;
		manager->types[i].objects = stage->types[i].objects;
		stage->types[i].objects = old;
	}
	manager->next_sequence = stage->next_sequence;
	manager->generation++;
	stage->committed = true;
	error = 0;
out:
	pthread_mutex_unlock(&manager->mutex);
	return (error);
}

int
virtio_admin_resource_restore_stage_count(
    struct virtio_admin_resource_restore_stage *stage, uint16_t type,
    virtio_admin_resource_match_cb match, void *argument, uint32_t *result)
{
	struct vadmin_resource_type *resource_type;
	uint32_t count;

	if (stage == NULL || result == NULL || stage->committed)
		return (EINVAL);
	if (vadmin_resource_stage_overlaps(stage, result, sizeof(*result)))
		return (EINVAL);
	resource_type = vadmin_resource_find_staged_type(stage->types,
	    stage->type_count, type);
	if (resource_type == NULL)
		return (ENOENT);
	count = 0;
	for (uint32_t id = 0; id < resource_type->config.limit; id++) {
		struct vadmin_resource_object *object;

		object = &resource_type->objects[id];
		if (!object->present)
			continue;
		if (match == NULL || match(argument, object->flags,
		    object->data, object->size))
			count++;
	}
	*result = count;
	return (0);
}

int
virtio_admin_resource_restore_stage_query(
    struct virtio_admin_resource_restore_stage *stage, uint16_t type,
    uint32_t id, uint64_t *flags, void *data, size_t capacity, size_t *size)
{
	struct vadmin_resource_object *object;
	struct vadmin_resource_type *resource_type;

	if (stage == NULL || flags == NULL || size == NULL ||
	    stage->committed || (data == NULL && capacity != 0))
		return (EINVAL);
	if (vadmin_resource_stage_overlaps(stage, flags, sizeof(*flags)) ||
	    vadmin_resource_stage_overlaps(stage, data, capacity) ||
	    vadmin_resource_stage_overlaps(stage, size, sizeof(*size)) ||
	    virtio_state_ranges_overlap(flags, sizeof(*flags), data, capacity) ||
	    virtio_state_ranges_overlap(flags, sizeof(*flags), size,
	    sizeof(*size)) || virtio_state_ranges_overlap(data, capacity, size,
	    sizeof(*size)))
		return (EINVAL);
	resource_type = vadmin_resource_find_staged_type(stage->types,
	    stage->type_count, type);
	if (resource_type == NULL || id >= resource_type->config.limit)
		return (ENOENT);
	object = &resource_type->objects[id];
	if (!object->present)
		return (ENOENT);
	if (capacity < object->size)
		return (ENOSPC);
	*flags = object->flags;
	*size = object->size;
	if (object->size != 0)
		memcpy(data, object->data, object->size);
	return (0);
}

void
virtio_admin_resource_restore_stage_destroy(
    struct virtio_admin_resource_restore_stage *stage)
{

	if (stage == NULL)
		return;
	vadmin_resource_free_staged(stage->types, stage->type_count);
	free(stage);
}

int
virtio_admin_resource_restore(struct virtio_admin_resource_manager *manager,
    const void *buffer, size_t length)
{
	struct virtio_admin_resource_restore_stage *stage;
	int error;

	error = virtio_admin_resource_restore_prepare(manager, buffer, length,
	    &stage);
	if (error != 0)
		return (error);
	error = virtio_admin_resource_restore_commit(manager, stage);
	virtio_admin_resource_restore_stage_destroy(stage);
	return (error);
}
