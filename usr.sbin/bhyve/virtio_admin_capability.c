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
#include "virtio_admin_capability.h"
#include "virtio_state_range.h"

#define	VADMIN_CAPABILITY_STATE_MAGIC	0x31504143U	/* "CAP1" */
#define	VADMIN_CAPABILITY_STATE_VERSION	1U
#define	VADMIN_CAPABILITY_STATE_DIGEST_OFFSET	24U

struct vadmin_capability {
	uint8_t *device_data;
	uint8_t *driver_data;
	size_t size;
	virtio_admin_capability_validate_cb validate;
	void *validate_argument;
	virtio_admin_capability_apply_cb apply;
	void *apply_argument;
	uint16_t id;
	bool driver_set;
};

struct vadmin_capability_binding {
	struct virtio_admin_capability_manager *manager;
	uint16_t opcode;
};

struct virtio_admin_capability_manager {
	pthread_mutex_t mutex;
	struct vadmin_capability capabilities[
	    BHYVE_VIRTIO_ADMIN_CAPABILITY_MAX_COUNT];
	struct vadmin_capability_binding bindings[3];
	uint16_t maximum_id;
	uint8_t count;
	bool commands_registered;
};

static struct vadmin_capability *
vadmin_capability_find(struct virtio_admin_capability_manager *manager,
    uint16_t id)
{

	for (uint8_t i = 0; i < manager->count; i++) {
		if (manager->capabilities[i].id == id)
			return (&manager->capabilities[i]);
	}
	return (NULL);
}

static bool vadmin_capability_snapshot_overlaps_locked(
    struct virtio_admin_capability_manager *, const void *, size_t);

static bool
vadmin_capability_results_invalid_locked(
    struct virtio_admin_capability_manager *manager, void *data,
    size_t capacity, size_t *size, bool *driver_set)
{

	return (vadmin_capability_snapshot_overlaps_locked(manager, data,
	    capacity) || vadmin_capability_snapshot_overlaps_locked(manager,
	    size, sizeof(*size)) ||
	    vadmin_capability_snapshot_overlaps_locked(manager, driver_set,
	    sizeof(*driver_set)) ||
	    virtio_state_ranges_overlap(data, capacity, size, sizeof(*size)) ||
	    virtio_state_ranges_overlap(data, capacity, driver_set,
	    sizeof(*driver_set)) ||
	    virtio_state_ranges_overlap(size, sizeof(*size), driver_set,
	    sizeof(*driver_set)));
}

static size_t
vadmin_capability_align(size_t value)
{

	return ((value + sizeof(uint64_t) - 1) &
	    ~(sizeof(uint64_t) - 1));
}

static uint64_t
vadmin_capability_digest(const uint8_t *bytes, size_t length)
{
	uint64_t digest;

	digest = UINT64_C(14695981039346656037);
	for (size_t i = 0; i < length; i++) {
		uint8_t byte;

		byte = i >= VADMIN_CAPABILITY_STATE_DIGEST_OFFSET &&
		    i < VADMIN_CAPABILITY_STATE_DIGEST_OFFSET +
		    sizeof(uint64_t) ? 0 : bytes[i];
		digest ^= byte;
		digest *= UINT64_C(1099511628211);
	}
	return (digest);
}

int
virtio_admin_capability_manager_create(
    struct virtio_admin_capability_manager **result)
{
	struct virtio_admin_capability_manager *manager;
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
	*result = manager;
	return (0);
}

void
virtio_admin_capability_manager_reset(
    struct virtio_admin_capability_manager *manager)
{

	if (manager == NULL)
		return;
	pthread_mutex_lock(&manager->mutex);
	for (uint8_t i = 0; i < manager->count; i++) {
		memset(manager->capabilities[i].driver_data, 0,
		    manager->capabilities[i].size);
		manager->capabilities[i].driver_set = false;
		if (manager->capabilities[i].apply != NULL)
			manager->capabilities[i].apply(
			    manager->capabilities[i].apply_argument,
			    manager->capabilities[i].driver_data,
			    manager->capabilities[i].size, false);
	}
	pthread_mutex_unlock(&manager->mutex);
}

void
virtio_admin_capability_manager_destroy(
    struct virtio_admin_capability_manager *manager)
{

	if (manager == NULL)
		return;
	for (uint8_t i = 0; i < manager->count; i++) {
		free(manager->capabilities[i].driver_data);
		free(manager->capabilities[i].device_data);
	}
	pthread_mutex_destroy(&manager->mutex);
	free(manager);
}

int
virtio_admin_capability_register(
    struct virtio_admin_capability_manager *manager,
    const struct virtio_admin_capability_config *config)
{
	struct vadmin_capability *capability;
	uint8_t *device_data, *driver_data;
	int error;

	if (manager == NULL || config == NULL)
		return (EINVAL);
	pthread_mutex_lock(&manager->mutex);
	error = vadmin_capability_snapshot_overlaps_locked(manager, config,
	    sizeof(*config));
	if (!error && config->device_data != NULL)
		error = vadmin_capability_snapshot_overlaps_locked(manager,
		    config->device_data, config->size);
	pthread_mutex_unlock(&manager->mutex);
	if (error)
		return (EINVAL);
	if (config->device_data == NULL ||
	    config->id > BHYVE_VIRTIO_ADMIN_CAPABILITY_MAX_ID ||
	    config->size == 0 ||
	    config->size > BHYVE_VIRTIO_ADMIN_CAPABILITY_MAX_SIZE)
		return (EINVAL);
	device_data = malloc(config->size);
	driver_data = calloc(1, config->size);
	if (device_data == NULL || driver_data == NULL) {
		free(driver_data);
		free(device_data);
		return (ENOMEM);
	}
	memcpy(device_data, config->device_data, config->size);
	pthread_mutex_lock(&manager->mutex);
	if (manager->commands_registered) {
		error = EBUSY;
	} else if (manager->count >= BHYVE_VIRTIO_ADMIN_CAPABILITY_MAX_COUNT) {
		error = ENOSPC;
	} else if (vadmin_capability_find(manager, config->id) != NULL) {
		error = EEXIST;
	} else {
		capability = &manager->capabilities[manager->count++];
		*capability = (struct vadmin_capability) {
			.device_data = device_data,
			.driver_data = driver_data,
			.size = config->size,
			.validate = config->validate,
			.validate_argument = config->validate_argument,
			.apply = config->apply,
			.apply_argument = config->apply_argument,
			.id = config->id,
		};
		if (config->id > manager->maximum_id)
			manager->maximum_id = config->id;
		device_data = NULL;
		driver_data = NULL;
		error = 0;
	}
	pthread_mutex_unlock(&manager->mutex);
	free(driver_data);
	free(device_data);
	return (error);
}

int
virtio_admin_capability_set_driver(
    struct virtio_admin_capability_manager *manager, uint16_t id,
    const void *data, size_t size)
{
	struct vadmin_capability *capability;
	uint8_t *proposed;
	int error;

	if (manager == NULL || (size != 0 && data == NULL))
		return (EINVAL);
	pthread_mutex_lock(&manager->mutex);
	capability = vadmin_capability_find(manager, id);
	if (capability == NULL) {
		pthread_mutex_unlock(&manager->mutex);
		return (ENXIO);
	}
	if (vadmin_capability_snapshot_overlaps_locked(manager, data, size)) {
		pthread_mutex_unlock(&manager->mutex);
		return (EINVAL);
	}
	proposed = calloc(1, capability->size);
	if (proposed == NULL) {
		pthread_mutex_unlock(&manager->mutex);
		return (ENOMEM);
	}
	if (size != 0)
		memcpy(proposed, data, MIN(size, capability->size));
	error = capability->validate == NULL ? 0 :
	    capability->validate(capability->validate_argument,
	    capability->device_data, capability->size, proposed,
	    capability->size);
	if (error == 0) {
		memcpy(capability->driver_data, proposed, capability->size);
		capability->driver_set = true;
		if (capability->apply != NULL)
			capability->apply(capability->apply_argument,
			    capability->driver_data, capability->size, true);
	}
	free(proposed);
	pthread_mutex_unlock(&manager->mutex);
	return (error);
}

int
virtio_admin_capability_set_driver_exact(
    struct virtio_admin_capability_manager *manager, uint16_t id,
    const void *data, size_t size)
{
	struct vadmin_capability *capability;
	int error;

	if (manager == NULL || data == NULL)
		return (EINVAL);
	pthread_mutex_lock(&manager->mutex);
	capability = vadmin_capability_find(manager, id);
	if (capability == NULL)
		error = ENXIO;
	else if (size != capability->size)
		error = EMSGSIZE;
	else if (vadmin_capability_snapshot_overlaps_locked(manager, data,
	    size))
		error = EINVAL;
	else {
		error = capability->validate == NULL ? 0 :
		    capability->validate(capability->validate_argument,
		    capability->device_data, capability->size, data, size);
		if (error == 0) {
			memcpy(capability->driver_data, data, size);
			capability->driver_set = true;
			if (capability->apply != NULL)
				capability->apply(capability->apply_argument,
				    capability->driver_data, capability->size,
				    true);
		}
	}
	pthread_mutex_unlock(&manager->mutex);
	return (error);
}

int
virtio_admin_capability_get_driver(
    struct virtio_admin_capability_manager *manager, uint16_t id,
    void *data, size_t capacity, size_t *size, bool *driver_set)
{
	struct vadmin_capability *capability;

	if (manager == NULL || size == NULL || driver_set == NULL ||
	    (capacity != 0 && data == NULL))
		return (EINVAL);
	pthread_mutex_lock(&manager->mutex);
	if (vadmin_capability_results_invalid_locked(manager, data, capacity,
	    size, driver_set)) {
		pthread_mutex_unlock(&manager->mutex);
		return (EINVAL);
	}
	capability = vadmin_capability_find(manager, id);
	if (capability == NULL) {
		pthread_mutex_unlock(&manager->mutex);
		return (ENXIO);
	}
	*size = capability->size;
	*driver_set = capability->driver_set;
	if (capacity != 0)
		memcpy(data, capability->driver_data,
		    MIN(capacity, capability->size));
	pthread_mutex_unlock(&manager->mutex);
	return (0);
}

static void
vadmin_capability_result_error(struct virtio_admin_command_result *result,
    int error)
{

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

static int
vadmin_capability_decode_id(const void *input, size_t input_length,
    uint16_t *id, const uint8_t **specific, size_t *specific_length)
{
	uint8_t header[8];

	memset(header, 0, sizeof(header));
	if (input_length != 0 && input == NULL)
		return (EINVAL);
	if (input_length != 0)
		memcpy(header, input, MIN(input_length, sizeof(header)));
	for (size_t i = 2; i < sizeof(header); i++) {
		if (header[i] != 0)
			return (EINVAL);
	}
	*id = le16dec(header);
	if (specific != NULL)
		*specific = input_length > sizeof(header) ?
		    (const uint8_t *)input + sizeof(header) : NULL;
	if (specific_length != NULL)
		*specific_length = input_length > sizeof(header) ?
		    input_length - sizeof(header) : 0;
	return (0);
}

static void
vadmin_capability_command(void *argument, uint64_t member_id,
    const void *input, size_t input_length, void *output,
    size_t output_length, struct virtio_admin_command_result *result)
{
	struct vadmin_capability_binding *binding;
	struct virtio_admin_capability_manager *manager;
	struct vadmin_capability *capability;
	const uint8_t *specific;
	size_t bitmap_size, specific_length;
	uint16_t id;
	int error;

	binding = argument;
	manager = binding->manager;
	if (member_id != 0) {
		result->status = BHYVE_VIRTIO_ADMIN_STATUS_EINVAL;
		result->qualifier =
		    BHYVE_VIRTIO_ADMIN_QUALIFIER_INVALID_MEMBER;
		return;
	}
	if (binding->opcode ==
	    BHYVE_VIRTIO_ADMIN_CMD_CAP_ID_LIST_QUERY) {
		/*
		 * This command has no command-specific input.  A longer
		 * device-readable structure is nevertheless valid and its
		 * extension bytes are ignored (VirtIO 1.4 section 2.13.1).
		 */
		pthread_mutex_lock(&manager->mutex);
		bitmap_size = manager->count == 0 ? 0 :
		    ((size_t)manager->maximum_id / 64 + 1) * 8;
		if (output_length != 0)
			memset(output, 0, MIN(output_length, bitmap_size));
		for (uint8_t i = 0; i < manager->count; i++) {
			size_t byte;

			byte = manager->capabilities[i].id / 8;
			if (byte < output_length)
				((uint8_t *)output)[byte] |=
				    1U << (manager->capabilities[i].id % 8);
		}
		pthread_mutex_unlock(&manager->mutex);
		result->result_length = bitmap_size;
		return;
	}
	error = vadmin_capability_decode_id(input, input_length, &id,
	    &specific, &specific_length);
	if (error != 0) {
		vadmin_capability_result_error(result, error);
		return;
	}
	if (binding->opcode == BHYVE_VIRTIO_ADMIN_CMD_DRIVER_CAP_SET) {
		error = virtio_admin_capability_set_driver(manager, id,
		    specific, specific_length);
		if (error != 0)
			vadmin_capability_result_error(result, error);
		return;
	}
	pthread_mutex_lock(&manager->mutex);
	capability = vadmin_capability_find(manager, id);
	if (capability == NULL) {
		error = ENXIO;
	} else {
		if (output_length != 0)
			memcpy(output, capability->device_data,
			    MIN(output_length, capability->size));
		result->result_length = capability->size;
		error = 0;
	}
	pthread_mutex_unlock(&manager->mutex);
	if (error != 0)
		vadmin_capability_result_error(result, error);
}

int
virtio_admin_capability_register_commands(
    struct virtio_admin_capability_manager *manager,
    struct virtio_admin_owner *owner)
{
	static const uint16_t opcodes[] = {
		BHYVE_VIRTIO_ADMIN_CMD_CAP_ID_LIST_QUERY,
		BHYVE_VIRTIO_ADMIN_CMD_DEVICE_CAP_GET,
		BHYVE_VIRTIO_ADMIN_CMD_DRIVER_CAP_SET,
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
		manager->bindings[i] = (struct vadmin_capability_binding) {
			.manager = manager,
			.opcode = opcodes[i],
		};
		registrations[i] =
		    (struct virtio_admin_command_registration) {
			.opcode = opcodes[i],
			.handler = vadmin_capability_command,
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
vadmin_capability_state_size_locked(
    struct virtio_admin_capability_manager *manager, size_t *result)
{
	size_t total;

	total = BHYVE_VIRTIO_ADMIN_CAPABILITY_STATE_HEADER_SIZE;
	for (uint8_t i = 0; i < manager->count; i++) {
		size_t entry_size;

		entry_size = BHYVE_VIRTIO_ADMIN_CAPABILITY_STATE_ENTRY_SIZE;
		if (manager->capabilities[i].size > SIZE_MAX - entry_size)
			return (EOVERFLOW);
		entry_size += manager->capabilities[i].size;
		if (entry_size > SIZE_MAX - (sizeof(uint64_t) - 1))
			return (EOVERFLOW);
		entry_size = vadmin_capability_align(entry_size);
		if (entry_size > SIZE_MAX - total)
			return (EOVERFLOW);
		total += entry_size;
		if (total > UINT32_MAX)
			return (EOVERFLOW);
	}
	*result = total;
	return (0);
}

int
virtio_admin_capability_snapshot_size(
    struct virtio_admin_capability_manager *manager, size_t *result)
{
	size_t required;
	int error;

	if (manager == NULL || result == NULL)
		return (EINVAL);
	pthread_mutex_lock(&manager->mutex);
	error = vadmin_capability_state_size_locked(manager, &required);
	if (error == 0 && vadmin_capability_snapshot_overlaps_locked(manager,
	    result, sizeof(*result)))
		error = EINVAL;
	if (error == 0)
		*result = required;
	pthread_mutex_unlock(&manager->mutex);
	return (error);
}

static bool
vadmin_capability_snapshot_overlaps_locked(
    struct virtio_admin_capability_manager *manager, const void *buffer,
    size_t length)
{

	if (virtio_state_ranges_overlap(buffer, length, manager,
	    sizeof(*manager)))
		return (true);
	for (uint8_t i = 0; i < manager->count; i++) {
		if (virtio_state_ranges_overlap(buffer, length,
		    manager->capabilities[i].device_data,
		    manager->capabilities[i].size) ||
		    virtio_state_ranges_overlap(buffer, length,
		    manager->capabilities[i].driver_data,
		    manager->capabilities[i].size))
			return (true);
	}
	return (false);
}

bool
virtio_admin_capability_snapshot_overlaps(
    struct virtio_admin_capability_manager *manager, const void *buffer,
    size_t length)
{
	bool overlaps;

	if (manager == NULL)
		return (false);
	pthread_mutex_lock(&manager->mutex);
	overlaps = vadmin_capability_snapshot_overlaps_locked(manager, buffer,
	    length);
	pthread_mutex_unlock(&manager->mutex);
	return (overlaps);
}

int
virtio_admin_capability_snapshot(
    struct virtio_admin_capability_manager *manager, void *buffer,
    size_t length)
{
	uint8_t *bytes;
	size_t cursor, required;
	int error;

	if (manager == NULL || buffer == NULL)
		return (EINVAL);
	bytes = buffer;
	pthread_mutex_lock(&manager->mutex);
	error = vadmin_capability_state_size_locked(manager, &required);
	if (error != 0 || length != required) {
		pthread_mutex_unlock(&manager->mutex);
		return (error != 0 ? error : EMSGSIZE);
	}
	if (vadmin_capability_snapshot_overlaps_locked(manager, buffer,
	    length)) {
		pthread_mutex_unlock(&manager->mutex);
		return (EINVAL);
	}
	memset(bytes, 0, length);
	le32enc(bytes, VADMIN_CAPABILITY_STATE_MAGIC);
	le16enc(bytes + 4, VADMIN_CAPABILITY_STATE_VERSION);
	le16enc(bytes + 6,
	    BHYVE_VIRTIO_ADMIN_CAPABILITY_STATE_HEADER_SIZE);
	le32enc(bytes + 8, (uint32_t)length);
	le32enc(bytes + 12, manager->count);
	cursor = BHYVE_VIRTIO_ADMIN_CAPABILITY_STATE_HEADER_SIZE;
	for (uint8_t i = 0; i < manager->count; i++) {
		struct vadmin_capability *capability;

		capability = &manager->capabilities[i];
		le16enc(bytes + cursor, capability->id);
		bytes[cursor + 2] = capability->driver_set ? 1 : 0;
		le32enc(bytes + cursor + 4, (uint32_t)capability->size);
		cursor += BHYVE_VIRTIO_ADMIN_CAPABILITY_STATE_ENTRY_SIZE;
		memcpy(bytes + cursor, capability->driver_data,
		    capability->size);
		cursor = vadmin_capability_align(cursor + capability->size);
	}
	le64enc(bytes + VADMIN_CAPABILITY_STATE_DIGEST_OFFSET,
	    vadmin_capability_digest(bytes, length));
	pthread_mutex_unlock(&manager->mutex);
	return (0);
}

int
virtio_admin_capability_restore(
    struct virtio_admin_capability_manager *manager, const void *buffer,
    size_t length)
{
	uint8_t *staged[BHYVE_VIRTIO_ADMIN_CAPABILITY_MAX_COUNT];
	bool staged_set[BHYVE_VIRTIO_ADMIN_CAPABILITY_MAX_COUNT];
	bool seen[BHYVE_VIRTIO_ADMIN_CAPABILITY_MAX_COUNT];
	const uint8_t *bytes;
	size_t cursor;
	uint32_t count;
	int error;

	if (manager == NULL || buffer == NULL)
		return (EINVAL);
	if (length < BHYVE_VIRTIO_ADMIN_CAPABILITY_STATE_HEADER_SIZE ||
	    length > UINT32_MAX)
		return (EMSGSIZE);
	if (virtio_admin_capability_snapshot_overlaps(manager, buffer, length))
		return (EINVAL);
	bytes = buffer;
	if (le32dec(bytes) != VADMIN_CAPABILITY_STATE_MAGIC ||
	    le16dec(bytes + 4) != VADMIN_CAPABILITY_STATE_VERSION ||
	    le16dec(bytes + 6) !=
	    BHYVE_VIRTIO_ADMIN_CAPABILITY_STATE_HEADER_SIZE ||
	    le32dec(bytes + 8) != length ||
	    le64dec(bytes + VADMIN_CAPABILITY_STATE_DIGEST_OFFSET) !=
	    vadmin_capability_digest(bytes, length))
		return (EPROTO);
	if (le64dec(bytes + 16) != 0)
		return (EPROTO);
	count = le32dec(bytes + 12);
	if (count > BHYVE_VIRTIO_ADMIN_CAPABILITY_MAX_COUNT ||
	    count > (length -
	    BHYVE_VIRTIO_ADMIN_CAPABILITY_STATE_HEADER_SIZE) /
	    BHYVE_VIRTIO_ADMIN_CAPABILITY_STATE_ENTRY_SIZE)
		return (EPROTO);

	memset(staged, 0, sizeof(staged));
	memset(staged_set, 0, sizeof(staged_set));
	memset(seen, 0, sizeof(seen));
	pthread_mutex_lock(&manager->mutex);
	if (count != manager->count) {
		error = ENOTSUP;
		goto fail;
	}
	cursor = BHYVE_VIRTIO_ADMIN_CAPABILITY_STATE_HEADER_SIZE;
	for (uint32_t entry = 0; entry < count; entry++) {
		struct vadmin_capability *capability;
		size_t end, index;
		uint32_t capability_size;
		uint16_t id;
		bool driver_set;

		if (cursor > length || length - cursor <
		    BHYVE_VIRTIO_ADMIN_CAPABILITY_STATE_ENTRY_SIZE) {
			error = EPROTO;
			goto fail;
		}
		id = le16dec(bytes + cursor);
		driver_set = bytes[cursor + 2] != 0;
		capability_size = le32dec(bytes + cursor + 4);
		if (bytes[cursor + 2] > 1 || bytes[cursor + 3] != 0 ||
		    le64dec(bytes + cursor + 8) != 0) {
			error = EPROTO;
			goto fail;
		}
		capability = vadmin_capability_find(manager, id);
		if (capability == NULL || capability->size != capability_size) {
			error = ENOTSUP;
			goto fail;
		}
		index = (size_t)(capability - manager->capabilities);
		if (seen[index]) {
			error = EPROTO;
			goto fail;
		}
		seen[index] = true;
		cursor += BHYVE_VIRTIO_ADMIN_CAPABILITY_STATE_ENTRY_SIZE;
		if (capability_size > length - cursor) {
			error = EPROTO;
			goto fail;
		}
		staged[index] = malloc(capability_size);
		if (staged[index] == NULL) {
			error = ENOMEM;
			goto fail;
		}
		memcpy(staged[index], bytes + cursor, capability_size);
		if (!driver_set) {
			for (uint32_t byte = 0; byte < capability_size; byte++) {
				if (staged[index][byte] != 0) {
					error = EPROTO;
					goto fail;
				}
			}
		} else if (capability->validate != NULL &&
		    capability->validate(capability->validate_argument,
		    capability->device_data, capability->size, staged[index],
		    capability->size) != 0) {
			error = ENOTSUP;
			goto fail;
		}
		staged_set[index] = driver_set;
		cursor += capability_size;
		if (cursor > SIZE_MAX - (sizeof(uint64_t) - 1)) {
			error = EOVERFLOW;
			goto fail;
		}
		end = vadmin_capability_align(cursor);
		if (end > length) {
			error = EPROTO;
			goto fail;
		}
		while (cursor < end) {
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
	for (uint8_t i = 0; i < manager->count; i++) {
		if (!seen[i]) {
			error = ENOTSUP;
			goto fail;
		}
		memcpy(manager->capabilities[i].driver_data, staged[i],
		    manager->capabilities[i].size);
		manager->capabilities[i].driver_set = staged_set[i];
	}
	for (uint8_t i = 0; i < manager->count; i++) {
		if (manager->capabilities[i].apply != NULL)
			manager->capabilities[i].apply(
			    manager->capabilities[i].apply_argument,
			    manager->capabilities[i].driver_data,
			    manager->capabilities[i].size, staged_set[i]);
	}
	error = 0;
fail:
	pthread_mutex_unlock(&manager->mutex);
	for (uint8_t i = 0; i < BHYVE_VIRTIO_ADMIN_CAPABILITY_MAX_COUNT; i++)
		free(staged[i]);
	return (error);
}
