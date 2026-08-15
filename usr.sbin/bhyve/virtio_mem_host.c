/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/endian.h>

#include <errno.h>
#include <assert.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "virtio_mem_host.h"
#include "virtio_state_range.h"

#define	VTMEM_REQ_PLUG		0U
#define	VTMEM_REQ_UNPLUG	1U
#define	VTMEM_REQ_UNPLUG_ALL	2U
#define	VTMEM_REQ_STATE		3U
#define	VTMEM_STATE_MAGIC	0x314d5456U	/* "VTM1" */
#define	VTMEM_STATE_VERSION	1U
#define	VTMEM_STATE_HEADER_SIZE	72U
#define	VTMEM_STATE_DIGEST_OFFSET 64U

struct virtio_mem_host {
	/*
	 * External set_range and config_changed callbacks deliberately run without
	 * either state lock.  Keep the object alive for every public operation so
	 * destroy cannot free their callback argument while they are executing.
	 */
	pthread_mutex_t lifetime_mutex;
	pthread_cond_t lifetime_cond;
	unsigned int active_calls;
	bool destroying;
	pthread_mutex_t state_mutex;
	pthread_mutex_t operation_mutex;
	struct virtio_mem_host_limits limits;
	struct virtio_mem_host_ops ops;
	uint8_t *bitmap;
	uint8_t *restore_bitmap;
	uint32_t block_count;
	uint32_t plugged_blocks;
	bool restore_incomplete;
};

static void vtmem_get_config(struct virtio_mem_host *,
    struct virtio_mem_host_config *);

static bool
vtmem_enter(struct virtio_mem_host *host)
{
	bool admitted;

	pthread_mutex_lock(&host->lifetime_mutex);
	admitted = !host->destroying;
	if (admitted)
		host->active_calls++;
	pthread_mutex_unlock(&host->lifetime_mutex);
	return (admitted);
}

static void
vtmem_leave(struct virtio_mem_host *host)
{

	pthread_mutex_lock(&host->lifetime_mutex);
	assert(host->active_calls != 0);
	host->active_calls--;
	if (host->destroying && host->active_calls == 0)
		pthread_cond_broadcast(&host->lifetime_cond);
	pthread_mutex_unlock(&host->lifetime_mutex);
}

static uint64_t
vtmem_digest(const uint8_t *bytes, size_t length)
{
	uint64_t digest;

	digest = UINT64_C(14695981039346656037);
	for (size_t i = 0; i < length; i++) {
		uint8_t byte;

		byte = i >= VTMEM_STATE_DIGEST_OFFSET &&
		    i < VTMEM_STATE_DIGEST_OFFSET + sizeof(uint64_t) ?
		    0 : bytes[i];
		digest ^= byte;
		digest *= UINT64_C(1099511628211);
	}
	return (digest);
}

static bool
vtmem_block_get(const uint8_t *bitmap, uint32_t block)
{

	return ((bitmap[block / 8] & (UINT8_C(1) << (block % 8))) != 0);
}

static void
vtmem_block_set(uint8_t *bitmap, uint32_t block, bool plugged)
{

	if (plugged)
		bitmap[block / 8] |= UINT8_C(1) << (block % 8);
	else
		bitmap[block / 8] &= ~(UINT8_C(1) << (block % 8));
}

static size_t
vtmem_bitmap_size(uint32_t blocks)
{

	/*
	 * Promote before rounding.  UINT32_MAX is a valid representable block
	 * count, and adding seven in uint32_t would wrap to six and silently
	 * under-allocate the bitmap.
	 */
	return (((size_t)blocks + 7U) / 8U);
}

static bool
vtmem_valid_size(const struct virtio_mem_host_limits *limits, uint64_t size)
{

	return (size <= limits->region_size &&
	    size % limits->block_size == 0);
}

static bool
vtmem_state_overlaps_host(struct virtio_mem_host *host, const void *buffer,
    size_t length)
{
	size_t bitmap_size;

	bitmap_size = vtmem_bitmap_size(host->block_count);
	return (virtio_state_ranges_overlap(buffer, length, host,
	    sizeof(*host)) ||
	    virtio_state_ranges_overlap(buffer, length, host->bitmap,
	    bitmap_size) ||
	    virtio_state_ranges_overlap(buffer, length, host->restore_bitmap,
	    bitmap_size));
}

int
virtio_mem_host_create(const struct virtio_mem_host_limits *limits,
    const struct virtio_mem_host_ops *ops, struct virtio_mem_host **result)
{
	struct virtio_mem_host *host;
	uint64_t blocks;

	if (limits == NULL || ops == NULL || result == NULL ||
	    virtio_state_ranges_overlap(limits, sizeof(*limits), result,
	    sizeof(*result)) ||
	    virtio_state_ranges_overlap(ops, sizeof(*ops), result,
	    sizeof(*result)) ||
	    ops->set_range == NULL || limits->block_size == 0 ||
	    (limits->block_size & (limits->block_size - 1)) != 0 ||
	    limits->address % limits->block_size != 0 ||
	    limits->region_size == 0 ||
	    !vtmem_valid_size(limits, limits->region_size) ||
	    !vtmem_valid_size(limits, limits->usable_region_size) ||
	    !vtmem_valid_size(limits, limits->requested_size) ||
	    limits->requested_size > limits->usable_region_size ||
	    limits->address > UINT64_MAX - (limits->region_size - 1) ||
	    limits->max_blocks == 0)
		return (EINVAL);
	blocks = limits->region_size / limits->block_size;
	if (blocks == 0 || blocks > limits->max_blocks ||
	    blocks > UINT32_MAX)
		return (E2BIG);
	host = calloc(1, sizeof(*host));
	if (host == NULL)
		return (ENOMEM);
	host->bitmap = calloc(vtmem_bitmap_size((uint32_t)blocks), 1);
	if (host->bitmap == NULL) {
		free(host);
		return (ENOMEM);
	}
	host->restore_bitmap =
	    calloc(vtmem_bitmap_size((uint32_t)blocks), 1);
	if (host->restore_bitmap == NULL) {
		free(host->bitmap);
		free(host);
		return (ENOMEM);
	}
	if (pthread_mutex_init(&host->state_mutex, NULL) != 0) {
		free(host->restore_bitmap);
		free(host->bitmap);
		free(host);
		return (ENOMEM);
	}
	if (pthread_mutex_init(&host->operation_mutex, NULL) != 0) {
		pthread_mutex_destroy(&host->state_mutex);
		free(host->restore_bitmap);
		free(host->bitmap);
		free(host);
		return (ENOMEM);
	}
	if (pthread_mutex_init(&host->lifetime_mutex, NULL) != 0) {
		pthread_mutex_destroy(&host->operation_mutex);
		pthread_mutex_destroy(&host->state_mutex);
		free(host->restore_bitmap);
		free(host->bitmap);
		free(host);
		return (ENOMEM);
	}
	if (pthread_cond_init(&host->lifetime_cond, NULL) != 0) {
		pthread_mutex_destroy(&host->lifetime_mutex);
		pthread_mutex_destroy(&host->operation_mutex);
		pthread_mutex_destroy(&host->state_mutex);
		free(host->restore_bitmap);
		free(host->bitmap);
		free(host);
		return (ENOMEM);
	}
	host->limits = *limits;
	host->ops = *ops;
	host->block_count = (uint32_t)blocks;
	*result = host;
	return (0);
}

void
virtio_mem_host_destroy(struct virtio_mem_host *host)
{

	if (host == NULL)
		return;
	pthread_mutex_lock(&host->lifetime_mutex);
	host->destroying = true;
	while (host->active_calls != 0)
		pthread_cond_wait(&host->lifetime_cond, &host->lifetime_mutex);
	pthread_mutex_unlock(&host->lifetime_mutex);
	pthread_cond_destroy(&host->lifetime_cond);
	pthread_mutex_destroy(&host->lifetime_mutex);
	pthread_mutex_destroy(&host->operation_mutex);
	pthread_mutex_destroy(&host->state_mutex);
	free(host->restore_bitmap);
	free(host->bitmap);
	free(host);
}

int
virtio_mem_host_set_requested_size(struct virtio_mem_host *host, uint64_t size)
{
	struct virtio_mem_host_config config;
	bool changed;

	if (host == NULL)
		return (EINVAL);
	if (!vtmem_enter(host))
		return (EBUSY);
	pthread_mutex_lock(&host->operation_mutex);
	if (host->restore_incomplete) {
		pthread_mutex_unlock(&host->operation_mutex);
		vtmem_leave(host);
		return (EBUSY);
	}
	pthread_mutex_lock(&host->state_mutex);
	if (!vtmem_valid_size(&host->limits, size)) {
		pthread_mutex_unlock(&host->state_mutex);
		pthread_mutex_unlock(&host->operation_mutex);
		vtmem_leave(host);
		return (EINVAL);
	}
	changed = host->limits.requested_size != size;
	host->limits.requested_size = size;
	if (host->limits.usable_region_size < size) {
		host->limits.usable_region_size = size;
		changed = true;
	}
	pthread_mutex_unlock(&host->state_mutex);
	pthread_mutex_unlock(&host->operation_mutex);
	/*
	 * VirtIO 1.4 section 5.15.4.2 requires a configuration update when
	 * requested_size or usable_region_size changes outside UNPLUG_ALL.
	 * Invoke the transport only after publishing the fields and dropping
	 * both host locks so it can safely perform a stable config read.
	 */
	if (changed && host->ops.config_changed != NULL) {
		vtmem_get_config(host, &config);
		host->ops.config_changed(host->ops.arg, &config);
	}
	vtmem_leave(host);
	return (0);
}

static void
vtmem_get_config(struct virtio_mem_host *host,
    struct virtio_mem_host_config *config)
{

	memset(config, 0, sizeof(*config));
	pthread_mutex_lock(&host->state_mutex);
	config->block_size = host->limits.block_size;
	config->address = host->limits.address;
	config->region_size = host->limits.region_size;
	config->usable_region_size = host->limits.usable_region_size;
	config->plugged_size =
	    (uint64_t)host->plugged_blocks * host->limits.block_size;
	config->requested_size = host->limits.requested_size;
	pthread_mutex_unlock(&host->state_mutex);
}

void
virtio_mem_host_get_config(struct virtio_mem_host *host,
    struct virtio_mem_host_config *config)
{

	if (host == NULL || config == NULL)
		return;
	if (!vtmem_enter(host))
		return;
	if (vtmem_state_overlaps_host(host, config, sizeof(*config)))
		goto out;
	vtmem_get_config(host, config);
out:
	vtmem_leave(host);
}

int
virtio_mem_host_config_encode(struct virtio_mem_host *host,
    uint8_t output[BHYVE_VTMEM_CONFIG_SIZE])
{
	struct virtio_mem_host_config config;

	if (host == NULL || output == NULL)
		return (EINVAL);
	if (!vtmem_enter(host))
		return (EBUSY);
	if (vtmem_state_overlaps_host(host, output, BHYVE_VTMEM_CONFIG_SIZE))
		goto invalid;
	/*
	 * Do not call the public get_config entry point from inside an admitted
	 * operation.  Destroy marks the object as destroying before waiting for
	 * active calls; a nested admission would then fail and leave config
	 * uninitialized even though this outer call still owns the object.
	 */
	vtmem_get_config(host, &config);
	memset(output, 0, BHYVE_VTMEM_CONFIG_SIZE);
	le64enc(output + 0, config.block_size);
	/* node_id and its padding remain zero: ACPI_PXM is not advertised. */
	le64enc(output + 16, config.address);
	le64enc(output + 24, config.region_size);
	le64enc(output + 32, config.usable_region_size);
	le64enc(output + 40, config.plugged_size);
	le64enc(output + 48, config.requested_size);
	vtmem_leave(host);
	return (0);
invalid:
	vtmem_leave(host);
	return (EINVAL);
}

static bool
vtmem_decode_range(struct virtio_mem_host *host, const uint8_t *request,
    uint32_t *first, uint32_t *count)
{
	uint64_t address, bytes, offset;
	uint16_t blocks;

	address = le64dec(request + 8);
	blocks = le16dec(request + 16);
	if (blocks == 0 || address < host->limits.address ||
	    address % host->limits.block_size != 0 ||
	    host->limits.block_size > UINT64_MAX / blocks)
		return (false);
	bytes = host->limits.block_size * blocks;
	offset = address - host->limits.address;
	if (offset > host->limits.usable_region_size ||
	    bytes > host->limits.usable_region_size - offset)
		return (false);
	*first = (uint32_t)(offset / host->limits.block_size);
	*count = blocks;
	return (true);
}

static enum virtio_mem_response
vtmem_change(struct virtio_mem_host *host, uint32_t first,
    uint32_t count, bool plug)
{
	uint64_t address, bytes, plugged;
	int error;

	pthread_mutex_lock(&host->state_mutex);
	for (uint32_t i = 0; i < count; i++) {
		if (vtmem_block_get(host->bitmap, first + i) == plug) {
			pthread_mutex_unlock(&host->state_mutex);
			return (BHYVE_VTMEM_RESP_ERROR);
		}
	}
	plugged = (uint64_t)host->plugged_blocks * host->limits.block_size;
	bytes = (uint64_t)count * host->limits.block_size;
	if (plug && (plugged > host->limits.requested_size ||
	    bytes > host->limits.requested_size - plugged)) {
		pthread_mutex_unlock(&host->state_mutex);
		return (BHYVE_VTMEM_RESP_NACK);
	}
	address = host->limits.address +
	    (uint64_t)first * host->limits.block_size;
	pthread_mutex_unlock(&host->state_mutex);
	error = host->ops.set_range(host->ops.arg, address, bytes, plug);
	if (error != 0)
		return (error == EBUSY || error == EAGAIN ?
		    BHYVE_VTMEM_RESP_BUSY : BHYVE_VTMEM_RESP_ERROR);
	pthread_mutex_lock(&host->state_mutex);
	for (uint32_t i = 0; i < count; i++)
		vtmem_block_set(host->bitmap, first + i, plug);
	if (plug)
		host->plugged_blocks += count;
	else
		host->plugged_blocks -= count;
	pthread_mutex_unlock(&host->state_mutex);
	return (BHYVE_VTMEM_RESP_ACK);
}

static enum virtio_mem_response
vtmem_unplug_all(struct virtio_mem_host *host)
{
	int error;

	pthread_mutex_lock(&host->state_mutex);
	if (host->plugged_blocks == 0) {
		host->limits.usable_region_size = host->limits.requested_size;
		pthread_mutex_unlock(&host->state_mutex);
		return (BHYVE_VTMEM_RESP_ACK);
	}
	pthread_mutex_unlock(&host->state_mutex);
	error = host->ops.set_range(host->ops.arg, host->limits.address,
	    host->limits.region_size, false);
	if (error != 0)
		return (error == EBUSY || error == EAGAIN ?
		    BHYVE_VTMEM_RESP_BUSY : BHYVE_VTMEM_RESP_ERROR);
	pthread_mutex_lock(&host->state_mutex);
	memset(host->bitmap, 0, vtmem_bitmap_size(host->block_count));
	host->plugged_blocks = 0;
	host->limits.usable_region_size = host->limits.requested_size;
	pthread_mutex_unlock(&host->state_mutex);
	return (BHYVE_VTMEM_RESP_ACK);
}

int
virtio_mem_host_request(struct virtio_mem_host *host, const void *input,
    size_t input_length, void *output, size_t output_length, size_t *used)
{
	const uint8_t *request;
	uint8_t *response;
	enum virtio_mem_response status;
	uint16_t type, state;
	uint32_t first, count, plugged;

	if (host == NULL || input == NULL || output == NULL || used == NULL)
		return (EINVAL);
	if (!vtmem_enter(host))
		return (EBUSY);
	if (vtmem_state_overlaps_host(host, input, input_length) ||
	    vtmem_state_overlaps_host(host, output, output_length) ||
	    vtmem_state_overlaps_host(host, used, sizeof(*used)) ||
	    virtio_state_ranges_overlap(input, input_length, output,
	    output_length) ||
	    virtio_state_ranges_overlap(input, input_length, used,
	    sizeof(*used)) ||
	    virtio_state_ranges_overlap(output, output_length, used,
	    sizeof(*used)))
		goto invalid;
	*used = 0;
	if (input_length != BHYVE_VTMEM_REQUEST_SIZE ||
	    output_length < BHYVE_VTMEM_RESPONSE_SIZE)
		goto size_error;
	request = input;
	response = output;
	type = le16dec(request);
	state = 0;
	pthread_mutex_lock(&host->operation_mutex);
	if (host->restore_incomplete) {
		status = BHYVE_VTMEM_RESP_BUSY;
		pthread_mutex_unlock(&host->operation_mutex);
		goto respond;
	}
	if (type == VTMEM_REQ_UNPLUG_ALL) {
		status = vtmem_unplug_all(host);
		pthread_mutex_unlock(&host->operation_mutex);
		goto respond;
	}
	pthread_mutex_lock(&host->state_mutex);
	if (type > VTMEM_REQ_STATE ||
	    !vtmem_decode_range(host, request, &first, &count)) {
		status = BHYVE_VTMEM_RESP_ERROR;
		pthread_mutex_unlock(&host->state_mutex);
		pthread_mutex_unlock(&host->operation_mutex);
		goto respond;
	}
	pthread_mutex_unlock(&host->state_mutex);
	switch (type) {
	case VTMEM_REQ_PLUG:
		status = vtmem_change(host, first, count, true);
		break;
	case VTMEM_REQ_UNPLUG:
		status = vtmem_change(host, first, count, false);
		break;
	case VTMEM_REQ_STATE:
		pthread_mutex_lock(&host->state_mutex);
		plugged = 0;
		for (uint32_t i = 0; i < count; i++)
			plugged += vtmem_block_get(host->bitmap, first + i);
		state = plugged == 0 ? BHYVE_VTMEM_STATE_UNPLUGGED :
		    plugged == count ? BHYVE_VTMEM_STATE_PLUGGED :
		    BHYVE_VTMEM_STATE_MIXED;
		status = BHYVE_VTMEM_RESP_ACK;
		pthread_mutex_unlock(&host->state_mutex);
		break;
	default:
		status = BHYVE_VTMEM_RESP_ERROR;
		break;
	}
	pthread_mutex_unlock(&host->operation_mutex);
respond:
	memset(response, 0, BHYVE_VTMEM_RESPONSE_SIZE);
	le16enc(response, status);
	if (status == BHYVE_VTMEM_RESP_ACK &&
	    type == VTMEM_REQ_STATE)
		le16enc(response + 8, state);
	*used = BHYVE_VTMEM_RESPONSE_SIZE;
	vtmem_leave(host);
	return (0);
size_error:
	vtmem_leave(host);
	return (EMSGSIZE);
invalid:
	vtmem_leave(host);
	return (EINVAL);
}

int
virtio_mem_host_reset(struct virtio_mem_host *host)
{

	if (host == NULL)
		return (EINVAL);
	if (!vtmem_enter(host))
		return (EBUSY);
	/*
	 * VirtIO 1.4 5.15.5.2 requires a device reset to preserve the state and
	 * properties of plugged memory blocks.
	 */
	pthread_mutex_lock(&host->operation_mutex);
	if (host->restore_incomplete) {
		pthread_mutex_unlock(&host->operation_mutex);
		vtmem_leave(host);
		return (EBUSY);
	}
	pthread_mutex_unlock(&host->operation_mutex);
	vtmem_leave(host);
	return (0);
}

/*
 * Remove host ranges reconstructed by an earlier failed restore.  Bits are
 * cleared only after the corresponding platform operation succeeds, so a
 * later restore can safely retry recovery after a transient failure.
 *
 * The platform set_range callback is transactional per call: a non-zero
 * return leaves the requested range unchanged.
 */
static int
vtmem_restore_cleanup(struct virtio_mem_host *host)
{
	uint32_t count;
	int error;

	for (uint32_t first = 0; first < host->block_count;) {
		if (!vtmem_block_get(host->restore_bitmap, first)) {
			first++;
			continue;
		}
		for (count = 1; first + count < host->block_count &&
		    vtmem_block_get(host->restore_bitmap, first + count);
		    count++)
			;
		error = host->ops.set_range(host->ops.arg,
		    host->limits.address +
		    (uint64_t)first * host->limits.block_size,
		    (uint64_t)count * host->limits.block_size, false);
		if (error != 0) {
			host->restore_incomplete = true;
			return (error);
		}
		for (uint32_t i = 0; i < count; i++)
			vtmem_block_set(host->restore_bitmap, first + i, false);
		first += count;
	}
	host->restore_incomplete = false;
	return (0);
}

int
virtio_mem_host_system_reset(struct virtio_mem_host *host)
{
	enum virtio_mem_response status;

	if (host == NULL)
		return (EINVAL);
	if (!vtmem_enter(host))
		return (EBUSY);
	pthread_mutex_lock(&host->operation_mutex);
	if (host->restore_incomplete) {
		int error;

		error = vtmem_restore_cleanup(host);
		if (error != 0) {
			pthread_mutex_unlock(&host->operation_mutex);
			vtmem_leave(host);
			return (error);
		}
	}
	status = vtmem_unplug_all(host);
	pthread_mutex_unlock(&host->operation_mutex);
	vtmem_leave(host);
	switch (status) {
	case BHYVE_VTMEM_RESP_ACK:
		return (0);
	case BHYVE_VTMEM_RESP_BUSY:
		return (EBUSY);
	default:
		return (EIO);
	}
}

int
virtio_mem_host_snapshot_size(struct virtio_mem_host *host, size_t *size)
{

	if (host == NULL || size == NULL)
		return (EINVAL);
	if (!vtmem_enter(host))
		return (EBUSY);
	if (vtmem_state_overlaps_host(host, size, sizeof(*size))) {
		vtmem_leave(host);
		return (EINVAL);
	}
	*size = VTMEM_STATE_HEADER_SIZE + vtmem_bitmap_size(host->block_count);
	vtmem_leave(host);
	return (0);
}

int
virtio_mem_host_snapshot(struct virtio_mem_host *host, void *buffer,
    size_t length)
{
	uint8_t *bytes;
	size_t expected, bitmap_size;

	if (host == NULL || buffer == NULL)
		return (EINVAL);
	if (!vtmem_enter(host))
		return (EBUSY);
	expected = VTMEM_STATE_HEADER_SIZE +
	    vtmem_bitmap_size(host->block_count);
	if (length != expected)
		goto size_error;
	if (vtmem_state_overlaps_host(host, buffer, length))
		goto invalid;
	bytes = buffer;
	pthread_mutex_lock(&host->operation_mutex);
	if (host->restore_incomplete) {
		pthread_mutex_unlock(&host->operation_mutex);
		vtmem_leave(host);
		return (EBUSY);
	}
	pthread_mutex_lock(&host->state_mutex);
	memset(bytes, 0, length);
	le32enc(bytes + 0, VTMEM_STATE_MAGIC);
	le16enc(bytes + 4, VTMEM_STATE_VERSION);
	le16enc(bytes + 6, VTMEM_STATE_HEADER_SIZE);
	le64enc(bytes + 8, length);
	le64enc(bytes + 16, host->limits.block_size);
	le64enc(bytes + 24, host->limits.address);
	le64enc(bytes + 32, host->limits.region_size);
	le64enc(bytes + 40, host->limits.usable_region_size);
	le64enc(bytes + 48, host->limits.requested_size);
	le32enc(bytes + 56, host->block_count);
	le32enc(bytes + 60, host->plugged_blocks);
	bitmap_size = vtmem_bitmap_size(host->block_count);
	memcpy(bytes + VTMEM_STATE_HEADER_SIZE, host->bitmap, bitmap_size);
	le64enc(bytes + VTMEM_STATE_DIGEST_OFFSET,
	    vtmem_digest(bytes, length));
	pthread_mutex_unlock(&host->state_mutex);
	pthread_mutex_unlock(&host->operation_mutex);
	vtmem_leave(host);
	return (0);
size_error:
	vtmem_leave(host);
	return (EMSGSIZE);
invalid:
	vtmem_leave(host);
	return (EINVAL);
}

static int
vtmem_restore_validate_locked(struct virtio_mem_host *host, const void *buffer,
    size_t length, const uint8_t **bitmapp, uint32_t *pluggedp)
{
	const uint8_t *bytes, *bitmap;
	uint32_t blocks, counted, plugged, usable_blocks;
	size_t expected, bitmap_size;
	int error;

	if (host == NULL || buffer == NULL)
		return (EINVAL);
	if (vtmem_state_overlaps_host(host, buffer, length))
		return (EINVAL);
	/*
	 * The operation lock serializes restore with requests that can change
	 * requested_size or usable_region_size.  Take state_mutex while reading
	 * the remaining mutable geometry and bitmap accounting.  A restore must
	 * validate against the same destination state it will later publish into;
	 * validating before operation_mutex is acquired leaves a window for a
	 * successful request to invalidate the checked image.
	 */
	pthread_mutex_lock(&host->state_mutex);
	bytes = buffer;
	expected = VTMEM_STATE_HEADER_SIZE +
	    vtmem_bitmap_size(host->block_count);
	/*
	 * The geometry is immutable guest-visible configuration, not spare host
	 * capacity.  Requiring the exact encoded size here intentionally rejects
	 * both smaller and larger destination regions before reading the record.
	 * Supporting a larger host allocation would require a separate restored
	 * visible-geometry layer; simply accepting it would change region_size and
	 * the bitmap ABI observed by the already-running guest.
	 */
	if (length != expected || length < VTMEM_STATE_HEADER_SIZE ||
	    le32dec(bytes + 0) != VTMEM_STATE_MAGIC ||
	    le16dec(bytes + 4) != VTMEM_STATE_VERSION ||
	    le16dec(bytes + 6) != VTMEM_STATE_HEADER_SIZE ||
	    le64dec(bytes + 8) != length ||
	    le64dec(bytes + 16) != host->limits.block_size ||
	    le64dec(bytes + 24) != host->limits.address ||
	    le64dec(bytes + 32) != host->limits.region_size ||
	    !vtmem_valid_size(&host->limits, le64dec(bytes + 40)) ||
	    !vtmem_valid_size(&host->limits, le64dec(bytes + 48)) ||
	    le64dec(bytes + 48) > le64dec(bytes + 40) ||
	    le64dec(bytes + VTMEM_STATE_DIGEST_OFFSET) !=
	    vtmem_digest(bytes, length))
		goto protocol_error;
	blocks = le32dec(bytes + 56);
	plugged = le32dec(bytes + 60);
	if (blocks != host->block_count || plugged > blocks)
		goto invalid;
	bitmap = bytes + VTMEM_STATE_HEADER_SIZE;
	bitmap_size = vtmem_bitmap_size(blocks);
	if ((blocks % 8) != 0 &&
	    (bitmap[bitmap_size - 1] &
	    (uint8_t)~((UINT8_C(1) << (blocks % 8)) - 1)) != 0)
		goto invalid;
	counted = 0;
	usable_blocks =
	    (uint32_t)(le64dec(bytes + 40) / host->limits.block_size);
	for (uint32_t i = 0; i < blocks; i++) {
		counted += vtmem_block_get(bitmap, i);
		if (i >= usable_blocks && vtmem_block_get(bitmap, i))
			goto invalid;
	}
	if (counted != plugged)
		goto invalid;
	if (bitmapp != NULL)
		*bitmapp = bitmap;
	if (pluggedp != NULL)
		*pluggedp = plugged;
	error = 0;
	goto out;

protocol_error:
	error = EPROTO;
	goto out;
invalid:
	error = EINVAL;
out:
	pthread_mutex_unlock(&host->state_mutex);
	return (error);
}

int
virtio_mem_host_restore_validate(struct virtio_mem_host *host,
    const void *buffer, size_t length)
{
	int error;

	if (host == NULL)
		return (EINVAL);
	if (!vtmem_enter(host))
		return (EBUSY);
	pthread_mutex_lock(&host->operation_mutex);
	error = vtmem_restore_validate_locked(host, buffer, length, NULL, NULL);
	pthread_mutex_unlock(&host->operation_mutex);
	vtmem_leave(host);
	return (error);
}

int
virtio_mem_host_restore(struct virtio_mem_host *host, const void *buffer,
    size_t length)
{
	const uint8_t *bitmap;
	uint8_t *bytes;
	uint32_t blocks, plugged;
	size_t bitmap_size, expected;
	int error;

	if (host == NULL)
		return (EINVAL);
	if (!vtmem_enter(host))
		return (EBUSY);
	pthread_mutex_lock(&host->operation_mutex);
	bytes = NULL;
	expected = VTMEM_STATE_HEADER_SIZE +
	    vtmem_bitmap_size(host->block_count);
	if (buffer == NULL || vtmem_state_overlaps_host(host, buffer, length)) {
		error = EINVAL;
		goto out;
	}
	if (length != expected) {
		error = EPROTO;
		goto out;
	}
	/*
	 * A platform range callback is external code and may run for an
	 * arbitrarily long time.  Do not continue consuming the caller-owned
	 * image after its digest has been checked: use one private image for
	 * validation, reconstruction, and publication.
	 */
	bytes = malloc(length);
	if (bytes == NULL) {
		error = ENOMEM;
		goto out;
	}
	memcpy(bytes, buffer, length);
	error = vtmem_restore_validate_locked(host, bytes, length, &bitmap,
	    &plugged);
	if (error != 0)
		goto out;
	blocks = host->block_count;
	bitmap_size = vtmem_bitmap_size(host->block_count);
	if (host->restore_incomplete) {
		error = vtmem_restore_cleanup(host);
		if (error != 0)
			goto out;
	}
	pthread_mutex_lock(&host->state_mutex);
	if (host->plugged_blocks != 0) {
		if (host->plugged_blocks == plugged &&
		    host->limits.usable_region_size == le64dec(bytes + 40) &&
		    host->limits.requested_size == le64dec(bytes + 48) &&
		    memcmp(host->bitmap, bitmap, bitmap_size) == 0) {
			pthread_mutex_unlock(&host->state_mutex);
			error = 0;
			goto out;
		}
		pthread_mutex_unlock(&host->state_mutex);
		error = EBUSY;
		goto out;
	}
	pthread_mutex_unlock(&host->state_mutex);
	for (uint32_t first = 0; first < blocks;) {
		uint32_t count;
		int range_error;

		if (!vtmem_block_get(bitmap, first)) {
			first++;
			continue;
		}
		for (count = 1; first + count < blocks &&
		    vtmem_block_get(bitmap, first + count); count++)
			;
		range_error = host->ops.set_range(host->ops.arg,
		    host->limits.address +
		    (uint64_t)first * host->limits.block_size,
		    (uint64_t)count * host->limits.block_size, true);
		if (range_error != 0) {
			int cleanup_error;

			/*
			 * Roll back only ranges that this restore attempt
			 * successfully reconstructed.  The callback may manage
			 * resources outside the restored bitmap, so a blanket
			 * operation over the whole region is not a safe inverse.
			 */
			cleanup_error = vtmem_restore_cleanup(host);
			error = cleanup_error != 0 ? cleanup_error : range_error;
			goto out;
		}
		for (uint32_t i = 0; i < count; i++)
			vtmem_block_set(host->restore_bitmap, first + i, true);
		first += count;
	}
	pthread_mutex_lock(&host->state_mutex);
	memcpy(host->bitmap, bitmap, bitmap_size);
	host->plugged_blocks = plugged;
	host->limits.usable_region_size = le64dec(bytes + 40);
	host->limits.requested_size = le64dec(bytes + 48);
	pthread_mutex_unlock(&host->state_mutex);
	memset(host->restore_bitmap, 0, bitmap_size);
	host->restore_incomplete = false;
	error = 0;
out:
	free(bytes);
	pthread_mutex_unlock(&host->operation_mutex);
	vtmem_leave(host);
	return (error);
}

bool
virtio_mem_host_restore_incomplete(struct virtio_mem_host *host)
{
	bool incomplete;

	if (host == NULL)
		return (true);
	if (!vtmem_enter(host))
		return (true);
	pthread_mutex_lock(&host->operation_mutex);
	incomplete = host->restore_incomplete;
	pthread_mutex_unlock(&host->operation_mutex);
	vtmem_leave(host);
	return (incomplete);
}
