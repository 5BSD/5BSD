/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/uio.h>
#include <sys/endian.h>

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "virtio_admin.h"
#include "virtio_admin_group.h"
#include "virtio_admin_queue.h"
#include "virtio_state_range.h"

#define	VADMIN_QUEUE_STATE_MAGIC	0x31425141U	/* "AQB1" */
#define	VADMIN_QUEUE_STATE_VERSION	1U
#define	VADMIN_QUEUE_STATE_HEADER_SIZE	40U
#define	VADMIN_QUEUE_STATE_DIGEST_OFFSET	32U

#define	VADMIN_PCI_STATE_MAGIC		0x31435041U	/* "APC1" */
#define	VADMIN_PCI_STATE_VERSION	1U
#define	VADMIN_PCI_STATE_HEADER_SIZE	32U
#define	VADMIN_PCI_STATE_DIGEST_OFFSET	24U

struct vadmin_queue {
	pthread_mutex_t mutex;
	uint8_t *input;
	uint8_t *output;
};

struct virtio_admin_queue_bank {
	pthread_rwlock_t lifecycle;
	struct virtio_admin_group_fabric *fabric;
	struct vadmin_queue *queues;
	size_t input_capacity;
	size_t output_capacity;
	uint16_t count;
};

struct virtio_admin_pci_controller {
	struct virtio_admin_pci_queue_namespace name_space;
	struct virtio_admin_group_fabric *fabric;
	struct virtio_admin_queue_bank *bank;
	struct virtio_admin_owner *self_owner;
};

bool
virtio_admin_pci_queue_range_valid(uint32_t ordinary_count,
    uint32_t admin_index, uint32_t admin_count)
{

	return (ordinary_count <= UINT16_MAX && admin_index <= UINT16_MAX &&
	    admin_count != 0 && admin_count <= UINT16_MAX &&
	    admin_index >= ordinary_count &&
	    admin_count <= UINT32_C(0x10000) - admin_index);
}

int
virtio_admin_pci_queue_namespace_init(
    struct virtio_admin_pci_queue_namespace *result,
    uint32_t ordinary_count, uint32_t admin_index, uint32_t admin_count)
{
	struct virtio_admin_pci_queue_namespace candidate;

	if (result == NULL || !virtio_admin_pci_queue_range_valid(
	    ordinary_count, admin_index, admin_count))
		return (EINVAL);
	candidate = (struct virtio_admin_pci_queue_namespace) {
		.ordinary_count = (uint16_t)ordinary_count,
		.admin_index = (uint16_t)admin_index,
		.admin_count = (uint16_t)admin_count,
	};
	*result = candidate;
	return (0);
}

enum virtio_admin_pci_queue_kind
virtio_admin_pci_queue_resolve(
    const struct virtio_admin_pci_queue_namespace *name_space,
    uint32_t selected, uint16_t *local_index)
{
	uint32_t admin_offset;

	if (name_space == NULL || local_index == NULL || selected > UINT16_MAX)
		return (VIRTIO_ADMIN_PCI_QUEUE_UNAVAILABLE);
	if (selected < name_space->ordinary_count) {
		*local_index = (uint16_t)selected;
		return (VIRTIO_ADMIN_PCI_QUEUE_ORDINARY);
	}
	if (selected < name_space->admin_index)
		return (VIRTIO_ADMIN_PCI_QUEUE_UNAVAILABLE);
	admin_offset = selected - name_space->admin_index;
	if (admin_offset >= name_space->admin_count)
		return (VIRTIO_ADMIN_PCI_QUEUE_UNAVAILABLE);
	*local_index = (uint16_t)admin_offset;
	return (VIRTIO_ADMIN_PCI_QUEUE_ADMIN);
}

static bool
vadmin_pci_self_available(void *argument)
{

	return (argument != NULL);
}

static bool
vadmin_pci_self_member_valid(void *argument, uint64_t member)
{

	return (argument != NULL && member == 0);
}

int
virtio_admin_pci_controller_create(
    struct virtio_admin_pci_controller **result, uint32_t ordinary_count,
    uint32_t admin_index, uint32_t admin_count, size_t input_capacity,
    size_t output_capacity)
{
	struct virtio_admin_group_config config;
	struct virtio_admin_pci_controller *controller;
	int error;

	if (result == NULL)
		return (EINVAL);
	*result = NULL;
	controller = calloc(1, sizeof(*controller));
	if (controller == NULL)
		return (ENOMEM);
	error = virtio_admin_pci_queue_namespace_init(&controller->name_space,
	    ordinary_count, admin_index, admin_count);
	if (error != 0)
		goto fail;
	error = virtio_admin_group_fabric_create(&controller->fabric);
	if (error != 0)
		goto fail;
	config = (struct virtio_admin_group_config) {
		.group_type = BHYVE_VIRTIO_ADMIN_GROUP_SELF,
		.available = vadmin_pci_self_available,
		.member_valid = vadmin_pci_self_member_valid,
		.argument = controller,
	};
	error = virtio_admin_group_register(controller->fabric, &config,
	    &controller->self_owner);
	if (error != 0)
		goto fail;
	error = virtio_admin_queue_bank_create(&controller->bank,
	    controller->fabric, controller->name_space.admin_count,
	    input_capacity, output_capacity);
	if (error != 0)
		goto fail;
	*result = controller;
	return (0);

fail:
	virtio_admin_queue_bank_destroy(controller->bank);
	virtio_admin_group_fabric_destroy(controller->fabric);
	free(controller);
	return (error);
}

void
virtio_admin_pci_controller_destroy(
    struct virtio_admin_pci_controller *controller)
{

	if (controller == NULL)
		return;
	virtio_admin_queue_bank_destroy(controller->bank);
	virtio_admin_group_fabric_destroy(controller->fabric);
	free(controller);
}

const struct virtio_admin_pci_queue_namespace *
virtio_admin_pci_controller_namespace(
    const struct virtio_admin_pci_controller *controller)
{

	return (controller == NULL ? NULL : &controller->name_space);
}

struct virtio_admin_owner *
virtio_admin_pci_controller_self_owner(
    struct virtio_admin_pci_controller *controller)
{

	return (controller == NULL ? NULL : controller->self_owner);
}

struct virtio_admin_queue_bank *
virtio_admin_pci_controller_queue_bank(
    struct virtio_admin_pci_controller *controller)
{

	return (controller == NULL ? NULL : controller->bank);
}

int
virtio_admin_pci_controller_register_group(
    struct virtio_admin_pci_controller *controller,
    const struct virtio_admin_group_config *config,
    struct virtio_admin_owner **owner)
{

	if (controller == NULL)
		return (EINVAL);
	return (virtio_admin_group_register(controller->fabric, config, owner));
}

int
virtio_admin_pci_controller_seal(
    struct virtio_admin_pci_controller *controller)
{

	if (controller == NULL)
		return (EINVAL);
	return (virtio_admin_group_fabric_seal(controller->fabric));
}

int
virtio_admin_pci_controller_process(
    struct virtio_admin_pci_controller *controller, uint32_t selected,
    const struct iovec *iov, size_t iov_count, size_t readable_count,
    uint32_t *used_length)
{
	uint16_t local;

	if (controller == NULL)
		return (EINVAL);
	if (virtio_admin_pci_queue_resolve(&controller->name_space, selected,
	    &local) != VIRTIO_ADMIN_PCI_QUEUE_ADMIN)
		return (ENOENT);
	return (virtio_admin_queue_bank_process(controller->bank, local, iov,
	    iov_count, readable_count, used_length));
}

int
virtio_admin_pci_controller_process_chain(
    struct virtio_admin_pci_controller *controller, uint32_t selected,
    const struct iovec *iov, size_t iov_count, size_t readable_count,
    size_t writable_count, bool ordered, bool lengths_known,
    uint64_t writable_bytes, uint32_t *used_length)
{
	uint64_t calculated;

	if (controller == NULL || iov == NULL || used_length == NULL ||
	    !ordered || !lengths_known || readable_count == 0 ||
	    writable_count == 0 || readable_count > iov_count ||
	    writable_count != iov_count - readable_count)
		return (EINVAL);
	calculated = 0;
	for (size_t i = readable_count; i < iov_count; i++) {
		if (iov[i].iov_len > UINT64_MAX - calculated)
			return (EOVERFLOW);
		calculated += iov[i].iov_len;
	}
	if (calculated != writable_bytes)
		return (EINVAL);
	return (virtio_admin_pci_controller_process(controller, selected, iov,
	    iov_count, readable_count, used_length));
}

int
virtio_admin_pci_controller_drain_queue(
    struct virtio_admin_pci_controller *controller, uint32_t selected)
{
	uint16_t local;

	if (controller == NULL)
		return (EINVAL);
	if (virtio_admin_pci_queue_resolve(&controller->name_space, selected,
	    &local) != VIRTIO_ADMIN_PCI_QUEUE_ADMIN)
		return (ENOENT);
	return (virtio_admin_queue_bank_drain(controller->bank, local));
}

void
virtio_admin_pci_controller_reset(
    struct virtio_admin_pci_controller *controller)
{

	if (controller != NULL)
		virtio_admin_queue_bank_reset(controller->bank);
}

static uint64_t
vadmin_pci_controller_digest(const uint8_t *bytes, size_t length)
{
	uint64_t digest;

	digest = UINT64_C(14695981039346656037);
	for (size_t i = 0; i < length; i++) {
		uint8_t byte;

		byte = i >= VADMIN_PCI_STATE_DIGEST_OFFSET &&
		    i < VADMIN_PCI_STATE_DIGEST_OFFSET + sizeof(uint64_t) ?
		    0 : bytes[i];
		digest ^= byte;
		digest *= UINT64_C(1099511628211);
	}
	return (digest);
}

int
virtio_admin_pci_controller_snapshot_size(
    struct virtio_admin_pci_controller *controller, size_t *result)
{
	size_t payload;
	int error;

	if (controller == NULL || result == NULL)
		return (EINVAL);
	error = virtio_admin_queue_bank_snapshot_size(controller->bank,
	    &payload);
	if (error != 0)
		return (error);
	if (payload > SIZE_MAX - VADMIN_PCI_STATE_HEADER_SIZE)
		return (EOVERFLOW);
	*result = VADMIN_PCI_STATE_HEADER_SIZE + payload;
	return (0);
}

int
virtio_admin_pci_controller_snapshot(
    struct virtio_admin_pci_controller *controller, void *buffer,
    size_t length)
{
	uint8_t *bytes;
	size_t expected, payload;
	uint64_t digest;
	int error;

	if (controller == NULL || buffer == NULL)
		return (EINVAL);
	error = virtio_admin_pci_controller_snapshot_size(controller,
	    &expected);
	if (error != 0)
		return (error);
	if (length != expected)
		return (EMSGSIZE);
	if (virtio_state_ranges_overlap(buffer, length, controller,
	    sizeof(*controller)) ||
	    virtio_admin_queue_bank_storage_overlaps(controller->bank, buffer,
	    length))
		return (EINVAL);
	bytes = buffer;
	payload = length - VADMIN_PCI_STATE_HEADER_SIZE;
	error = virtio_admin_queue_bank_snapshot(controller->bank,
	    bytes + VADMIN_PCI_STATE_HEADER_SIZE, payload);
	if (error != 0)
		return (error);
	memset(bytes, 0, VADMIN_PCI_STATE_HEADER_SIZE);
	le32enc(bytes, VADMIN_PCI_STATE_MAGIC);
	le32enc(bytes + 4, VADMIN_PCI_STATE_VERSION);
	le16enc(bytes + 8, controller->name_space.ordinary_count);
	le16enc(bytes + 10, controller->name_space.admin_index);
	le16enc(bytes + 12, controller->name_space.admin_count);
	le64enc(bytes + 16, payload);
	digest = vadmin_pci_controller_digest(bytes, length);
	le64enc(bytes + VADMIN_PCI_STATE_DIGEST_OFFSET, digest);
	return (0);
}

static int
vadmin_pci_controller_restore(
    struct virtio_admin_pci_controller *controller, const void *buffer,
    size_t length, bool publish)
{
	const uint8_t *bytes;
	uint64_t payload;

	if (controller == NULL || buffer == NULL)
		return (EINVAL);
	if (length < VADMIN_PCI_STATE_HEADER_SIZE)
		return (EMSGSIZE);
	if (virtio_state_ranges_overlap(buffer, length, controller,
	    sizeof(*controller)) ||
	    virtio_admin_queue_bank_storage_overlaps(controller->bank, buffer,
	    length))
		return (EINVAL);
	bytes = buffer;
	payload = le64dec(bytes + 16);
	if (le32dec(bytes) != VADMIN_PCI_STATE_MAGIC ||
	    le32dec(bytes + 4) != VADMIN_PCI_STATE_VERSION ||
	    le16dec(bytes + 14) != 0 ||
	    payload != length - VADMIN_PCI_STATE_HEADER_SIZE ||
	    le64dec(bytes + VADMIN_PCI_STATE_DIGEST_OFFSET) !=
	    vadmin_pci_controller_digest(bytes, length))
		return (EPROTO);
	if (le16dec(bytes + 8) != controller->name_space.ordinary_count ||
	    le16dec(bytes + 10) != controller->name_space.admin_index ||
	    le16dec(bytes + 12) != controller->name_space.admin_count)
		return (ENOTSUP);
	if (publish)
		return (virtio_admin_queue_bank_restore(controller->bank,
		    bytes + VADMIN_PCI_STATE_HEADER_SIZE, (size_t)payload));
	return (virtio_admin_queue_bank_restore_validate(controller->bank,
	    bytes + VADMIN_PCI_STATE_HEADER_SIZE, (size_t)payload));
}

int
virtio_admin_pci_controller_restore_validate(
    struct virtio_admin_pci_controller *controller, const void *buffer,
    size_t length)
{

	return (vadmin_pci_controller_restore(controller, buffer, length, false));
}

int
virtio_admin_pci_controller_restore(
    struct virtio_admin_pci_controller *controller, const void *buffer,
    size_t length)
{

	return (vadmin_pci_controller_restore(controller, buffer, length, true));
}

static uint64_t
vadmin_queue_digest(const uint8_t *bytes, size_t length)
{
	uint64_t digest;

	digest = UINT64_C(14695981039346656037);
	for (size_t i = 0; i < length; i++) {
		uint8_t byte;

		byte = i >= VADMIN_QUEUE_STATE_DIGEST_OFFSET &&
		    i < VADMIN_QUEUE_STATE_DIGEST_OFFSET + sizeof(uint64_t) ?
		    0 : bytes[i];
		digest ^= byte;
		digest *= UINT64_C(1099511628211);
	}
	return (digest);
}

bool
virtio_admin_queue_bank_storage_overlaps(struct virtio_admin_queue_bank *bank,
    const void *buffer, size_t length)
{
	if (bank == NULL)
		return (false);

	if (virtio_state_ranges_overlap(buffer, length, bank, sizeof(*bank)) ||
	    virtio_state_ranges_overlap(buffer, length, bank->queues,
	    (size_t)bank->count * sizeof(*bank->queues)) ||
	    virtio_admin_group_snapshot_overlaps(bank->fabric, buffer,
	    length))
		return (true);
	for (uint16_t i = 0; i < bank->count; i++) {
		if (virtio_state_ranges_overlap(buffer, length,
		    bank->queues[i].input, bank->input_capacity) ||
		    virtio_state_ranges_overlap(buffer, length,
		    bank->queues[i].output, bank->output_capacity))
			return (true);
	}
	return (false);
}

static int
vadmin_iov_length(const struct iovec *iov, size_t count, size_t *length)
{
	size_t total;

	total = 0;
	for (size_t i = 0; i < count; i++) {
		if (iov[i].iov_base == NULL && iov[i].iov_len != 0)
			return (EFAULT);
		if (iov[i].iov_len > SIZE_MAX - total)
			return (EOVERFLOW);
		total += iov[i].iov_len;
	}
	*length = total;
	return (0);
}

static bool
vadmin_iov_storage_overlaps(const struct iovec *iov, size_t iov_count,
    size_t readable_count, const void *input_scratch, size_t input_capacity,
    const void *output_scratch, size_t output_capacity,
    const uint32_t *used_length)
{
	size_t metadata_length;

	metadata_length = iov_count * sizeof(*iov);
	if (virtio_state_ranges_overlap(iov, metadata_length, input_scratch,
	    input_capacity) ||
	    virtio_state_ranges_overlap(iov, metadata_length, output_scratch,
	    output_capacity) ||
	    virtio_state_ranges_overlap(iov, metadata_length, used_length,
	    sizeof(*used_length)) ||
	    virtio_state_ranges_overlap(input_scratch, input_capacity,
	    output_scratch, output_capacity) ||
	    virtio_state_ranges_overlap(input_scratch, input_capacity,
	    used_length, sizeof(*used_length)) ||
	    virtio_state_ranges_overlap(output_scratch, output_capacity,
	    used_length, sizeof(*used_length)))
		return (true);
	for (size_t i = 0; i < iov_count; i++) {
		if (virtio_state_ranges_overlap(iov[i].iov_base, iov[i].iov_len,
		    iov, metadata_length) ||
		    virtio_state_ranges_overlap(iov[i].iov_base, iov[i].iov_len,
		    input_scratch, input_capacity) ||
		    virtio_state_ranges_overlap(iov[i].iov_base, iov[i].iov_len,
		    output_scratch, output_capacity) ||
		    virtio_state_ranges_overlap(iov[i].iov_base, iov[i].iov_len,
		    used_length, sizeof(*used_length)))
			return (true);
		if (i < readable_count)
			continue;
		for (size_t j = i + 1; j < iov_count; j++) {
			if (virtio_state_ranges_overlap(iov[i].iov_base,
			    iov[i].iov_len, iov[j].iov_base, iov[j].iov_len))
				return (true);
		}
	}
	return (false);
}

static void
vadmin_iov_gather(const struct iovec *iov, size_t count, uint8_t *buffer)
{

	for (size_t i = 0; i < count; i++) {
		if (iov[i].iov_len == 0)
			continue;
		memcpy(buffer, iov[i].iov_base, iov[i].iov_len);
		buffer += iov[i].iov_len;
	}
}

static void
vadmin_iov_scatter(const uint8_t *buffer, size_t length,
    const struct iovec *iov, size_t count)
{
	size_t copied;

	copied = 0;
	for (size_t i = 0; i < count && copied < length; i++) {
		size_t chunk;

		chunk = iov[i].iov_len;
		if (chunk == 0)
			continue;
		if (chunk > length - copied)
			chunk = length - copied;
		memcpy(iov[i].iov_base, buffer + copied, chunk);
		copied += chunk;
	}
}

typedef int (*vadmin_process_cb)(void *, const void *, size_t, void *, size_t,
    size_t *);

static int
vadmin_owner_process(void *argument, const void *input, size_t input_length,
    void *output, size_t output_length, size_t *written)
{

	return (virtio_admin_process(argument, input, input_length, output,
	    output_length, written));
}

static int
vadmin_group_process(void *argument, const void *input, size_t input_length,
    void *output, size_t output_length, size_t *written)
{

	return (virtio_admin_group_process(argument, input, input_length, output,
	    output_length, written));
}

static int
vadmin_process_iov(void *processor, vadmin_process_cb process,
    const struct iovec *iov, size_t iov_count, size_t readable_count,
    void *input_scratch, size_t input_capacity, void *output_scratch,
    size_t output_capacity, uint32_t *used_length)
{
	size_t input_length, output_length, written;
	int error;

	if (processor == NULL || process == NULL || iov == NULL ||
	    iov_count == 0 ||
	    iov_count > BHYVE_VIRTIO_ADMIN_QUEUE_IOV_MAX ||
	    readable_count == 0 || readable_count >= iov_count ||
	    input_scratch == NULL || output_scratch == NULL ||
	    used_length == NULL)
		return (EINVAL);
	error = vadmin_iov_length(iov, readable_count, &input_length);
	if (error != 0)
		return (error);
	error = vadmin_iov_length(iov + readable_count,
	    iov_count - readable_count, &output_length);
	if (error != 0)
		return (error);
	if (vadmin_iov_storage_overlaps(iov, iov_count, readable_count,
	    input_scratch, input_capacity, output_scratch, output_capacity,
	    used_length))
		return (EINVAL);
	*used_length = 0;
	if (input_length == 0 || output_length == 0)
		return (EINVAL);
	if (input_length > input_capacity || output_length > output_capacity)
		return (EMSGSIZE);

	vadmin_iov_gather(iov, readable_count, input_scratch);
	error = process(processor, input_scratch, input_length,
	    output_scratch, output_length, &written);
	if (error != 0)
		return (error);
	if (written > output_length || written > UINT32_MAX)
		return (EOVERFLOW);
	vadmin_iov_scatter(output_scratch, written, iov + readable_count,
	    iov_count - readable_count);
	*used_length = (uint32_t)written;
	return (0);
}

int
virtio_admin_process_iov(struct virtio_admin_owner *owner,
    const struct iovec *iov, size_t iov_count, size_t readable_count,
    void *input_scratch, size_t input_capacity, void *output_scratch,
    size_t output_capacity, uint32_t *used_length)
{

	return (vadmin_process_iov(owner, vadmin_owner_process, iov, iov_count,
	    readable_count, input_scratch, input_capacity, output_scratch,
	    output_capacity, used_length));
}

int
virtio_admin_queue_bank_create(struct virtio_admin_queue_bank **result,
    struct virtio_admin_group_fabric *fabric, uint16_t count,
    size_t input_capacity, size_t output_capacity)
{
	struct virtio_admin_queue_bank *bank;
	size_t per_queue;
	uint16_t initialized;
	int error;

	if (result == NULL)
		return (EINVAL);
	*result = NULL;
	if (fabric == NULL || count == 0 ||
	    count > BHYVE_VIRTIO_ADMIN_QUEUE_MAX || input_capacity == 0 ||
	    output_capacity == 0 ||
	    input_capacity > BHYVE_VIRTIO_ADMIN_QUEUE_SCRATCH_MAX ||
	    output_capacity > BHYVE_VIRTIO_ADMIN_QUEUE_SCRATCH_MAX ||
	    input_capacity > SIZE_MAX - output_capacity)
		return (EINVAL);
	per_queue = input_capacity + output_capacity;
	if (per_queue > BHYVE_VIRTIO_ADMIN_QUEUE_SCRATCH_TOTAL_MAX / count)
		return (E2BIG);
	bank = calloc(1, sizeof(*bank));
	if (bank == NULL)
		return (ENOMEM);
	error = pthread_rwlock_init(&bank->lifecycle, NULL);
	if (error != 0) {
		free(bank);
		return (error);
	}
	bank->queues = calloc(count, sizeof(*bank->queues));
	if (bank->queues == NULL) {
		pthread_rwlock_destroy(&bank->lifecycle);
		free(bank);
		return (ENOMEM);
	}
	initialized = 0;
	for (uint16_t i = 0; i < count; i++) {
		error = pthread_mutex_init(&bank->queues[i].mutex, NULL);
		if (error != 0)
			goto fail;
		initialized++;
		bank->queues[i].input = malloc(input_capacity);
		bank->queues[i].output = malloc(output_capacity);
		if (bank->queues[i].input == NULL ||
		    bank->queues[i].output == NULL) {
			error = ENOMEM;
			goto fail;
		}
	}
	bank->fabric = fabric;
	bank->input_capacity = input_capacity;
	bank->output_capacity = output_capacity;
	bank->count = count;
	*result = bank;
	return (0);

fail:
	for (uint16_t i = 0; i < initialized; i++) {
		free(bank->queues[i].output);
		free(bank->queues[i].input);
		pthread_mutex_destroy(&bank->queues[i].mutex);
	}
	free(bank->queues);
	pthread_rwlock_destroy(&bank->lifecycle);
	free(bank);
	return (error);
}

void
virtio_admin_queue_bank_destroy(struct virtio_admin_queue_bank *bank)
{

	if (bank == NULL)
		return;
	/*
	 * The transport has stopped new kicks before destruction.  Taking the
	 * writer lease still drains any process call which already entered.
	 */
	pthread_rwlock_wrlock(&bank->lifecycle);
	pthread_rwlock_unlock(&bank->lifecycle);
	for (uint16_t i = 0; i < bank->count; i++) {
		free(bank->queues[i].output);
		free(bank->queues[i].input);
		pthread_mutex_destroy(&bank->queues[i].mutex);
	}
	free(bank->queues);
	pthread_rwlock_destroy(&bank->lifecycle);
	free(bank);
}

uint16_t
virtio_admin_queue_bank_count(const struct virtio_admin_queue_bank *bank)
{

	return (bank == NULL ? 0 : bank->count);
}

int
virtio_admin_queue_bank_process(struct virtio_admin_queue_bank *bank,
    uint16_t queue, const struct iovec *iov, size_t iov_count,
    size_t readable_count, uint32_t *used_length)
{
	struct vadmin_queue *adminq;
	int error;

	if (bank == NULL || queue >= bank->count)
		return (EINVAL);
	pthread_rwlock_rdlock(&bank->lifecycle);
	adminq = &bank->queues[queue];
	pthread_mutex_lock(&adminq->mutex);
	error = vadmin_process_iov(bank->fabric, vadmin_group_process, iov,
	    iov_count, readable_count, adminq->input, bank->input_capacity,
	    adminq->output, bank->output_capacity, used_length);
	pthread_mutex_unlock(&adminq->mutex);
	pthread_rwlock_unlock(&bank->lifecycle);
	return (error);
}

int
virtio_admin_queue_bank_drain(struct virtio_admin_queue_bank *bank,
    uint16_t queue)
{
	struct vadmin_queue *adminq;

	if (bank == NULL || queue >= bank->count)
		return (EINVAL);
	/*
	 * Match the processing lock order.  The lifecycle reader prevents a
	 * concurrent whole-bank reset or snapshot from crossing this queue-local
	 * fence, while the queue mutex waits only for the selected command stream.
	 */
	pthread_rwlock_rdlock(&bank->lifecycle);
	adminq = &bank->queues[queue];
	pthread_mutex_lock(&adminq->mutex);
	pthread_mutex_unlock(&adminq->mutex);
	pthread_rwlock_unlock(&bank->lifecycle);
	return (0);
}

void
virtio_admin_queue_bank_reset(struct virtio_admin_queue_bank *bank)
{

	if (bank == NULL)
		return;
	pthread_rwlock_wrlock(&bank->lifecycle);
	virtio_admin_group_fabric_reset(bank->fabric);
	pthread_rwlock_unlock(&bank->lifecycle);
}

int
virtio_admin_queue_bank_snapshot_size(struct virtio_admin_queue_bank *bank,
    size_t *result)
{
	size_t payload_size;
	int error;

	if (bank == NULL || result == NULL)
		return (EINVAL);
	pthread_rwlock_wrlock(&bank->lifecycle);
	error = virtio_admin_group_snapshot_size(bank->fabric, &payload_size);
	if (error == 0) {
		if (payload_size > SIZE_MAX - VADMIN_QUEUE_STATE_HEADER_SIZE)
			error = EOVERFLOW;
		else
			*result = VADMIN_QUEUE_STATE_HEADER_SIZE + payload_size;
	}
	pthread_rwlock_unlock(&bank->lifecycle);
	return (error);
}

int
virtio_admin_queue_bank_snapshot(struct virtio_admin_queue_bank *bank,
    void *buffer, size_t length)
{
	uint8_t header[VADMIN_QUEUE_STATE_HEADER_SIZE];
	uint8_t *bytes;
	size_t payload_size;
	uint64_t digest;
	int error;

	if (bank == NULL || buffer == NULL)
		return (EINVAL);
	pthread_rwlock_wrlock(&bank->lifecycle);
	error = virtio_admin_group_snapshot_size(bank->fabric, &payload_size);
	if (error != 0)
		goto done;
	if (payload_size > SIZE_MAX - VADMIN_QUEUE_STATE_HEADER_SIZE ||
	    length != VADMIN_QUEUE_STATE_HEADER_SIZE + payload_size) {
		error = EMSGSIZE;
		goto done;
	}
	if (virtio_admin_queue_bank_storage_overlaps(bank, buffer, length)) {
		error = EINVAL;
		goto done;
	}
	bytes = buffer;
	/*
	 * The group snapshot stages its own output.  Do not touch the caller's
	 * header until that operation succeeds, so every failure leaves the
	 * complete destination buffer unchanged.
	 */
	error = virtio_admin_group_snapshot(bank->fabric,
	    bytes + VADMIN_QUEUE_STATE_HEADER_SIZE, payload_size);
	if (error != 0)
		goto done;
	memset(header, 0, sizeof(header));
	le32enc(header + 0, VADMIN_QUEUE_STATE_MAGIC);
	le16enc(header + 4, VADMIN_QUEUE_STATE_VERSION);
	le16enc(header + 6, VADMIN_QUEUE_STATE_HEADER_SIZE);
	le16enc(header + 8, bank->count);
	le32enc(header + 12, (uint32_t)bank->input_capacity);
	le32enc(header + 16, (uint32_t)bank->output_capacity);
	le64enc(header + 24, payload_size);
	memcpy(bytes, header, sizeof(header));
	digest = vadmin_queue_digest(bytes, length);
	le64enc(bytes + VADMIN_QUEUE_STATE_DIGEST_OFFSET, digest);
	error = 0;
done:
	pthread_rwlock_unlock(&bank->lifecycle);
	return (error);
}

static int
vadmin_queue_bank_restore(struct virtio_admin_queue_bank *bank,
    const void *buffer, size_t length, bool publish)
{
	const uint8_t *bytes;
	uint64_t payload_size;
	int error;

	if (bank == NULL || buffer == NULL)
		return (EINVAL);
	if (virtio_admin_queue_bank_storage_overlaps(bank, buffer, length))
		return (EINVAL);
	bytes = buffer;
	if (length < VADMIN_QUEUE_STATE_HEADER_SIZE ||
	    le32dec(bytes + 0) != VADMIN_QUEUE_STATE_MAGIC ||
	    le16dec(bytes + 4) != VADMIN_QUEUE_STATE_VERSION ||
	    le16dec(bytes + 6) != VADMIN_QUEUE_STATE_HEADER_SIZE ||
	    le16dec(bytes + 10) != 0 || le32dec(bytes + 20) != 0 ||
	    le64dec(bytes + 32) != vadmin_queue_digest(bytes, length))
		return (EPROTO);
	payload_size = le64dec(bytes + 24);
	if (payload_size > SIZE_MAX ||
	    payload_size != length - VADMIN_QUEUE_STATE_HEADER_SIZE)
		return (EPROTO);
	if (le16dec(bytes + 8) != bank->count ||
	    le32dec(bytes + 12) != bank->input_capacity ||
	    le32dec(bytes + 16) != bank->output_capacity)
		return (ENOTSUP);
	pthread_rwlock_wrlock(&bank->lifecycle);
	if (publish)
		error = virtio_admin_group_restore(bank->fabric,
		    bytes + VADMIN_QUEUE_STATE_HEADER_SIZE,
		    (size_t)payload_size);
	else
		error = virtio_admin_group_restore_validate(bank->fabric,
		    bytes + VADMIN_QUEUE_STATE_HEADER_SIZE,
		    (size_t)payload_size);
	pthread_rwlock_unlock(&bank->lifecycle);
	return (error);
}

int
virtio_admin_queue_bank_restore_validate(
    struct virtio_admin_queue_bank *bank, const void *buffer, size_t length)
{

	return (vadmin_queue_bank_restore(bank, buffer, length, false));
}

int
virtio_admin_queue_bank_restore(struct virtio_admin_queue_bank *bank,
    const void *buffer, size_t length)
{

	return (vadmin_queue_bank_restore(bank, buffer, length, true));
}
