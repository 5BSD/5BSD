/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/endian.h>
#include <sys/param.h>

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "virtio_admin.h"
#include "virtio_admin_group.h"
#include "virtio_state_range.h"

#define	VADMIN_GROUP_STATE_MAGIC	0x31524741U	/* "AGR1" */
#define	VADMIN_GROUP_STATE_VERSION	1U
#define	VADMIN_GROUP_STATE_DIGEST_OFFSET	24U

struct vadmin_group {
	struct virtio_admin_owner *owner;
	struct virtio_admin_group_config config;
};

struct virtio_admin_group_fabric {
	pthread_rwlock_t lock;
	struct vadmin_group groups[BHYVE_VIRTIO_ADMIN_GROUP_MAX];
	uint8_t count;
	_Atomic(bool) sealed;
};

static struct vadmin_group *
vadmin_group_find(struct virtio_admin_group_fabric *fabric,
    uint16_t group_type)
{

	for (uint8_t i = 0; i < fabric->count; i++) {
		if (fabric->groups[i].config.group_type == group_type)
			return (&fabric->groups[i]);
	}
	return (NULL);
}

static uint64_t
vadmin_group_digest(const uint8_t *bytes, size_t length)
{
	uint64_t digest;

	digest = UINT64_C(14695981039346656037);
	for (size_t i = 0; i < length; i++) {
		uint8_t byte;

		byte = i >= VADMIN_GROUP_STATE_DIGEST_OFFSET &&
		    i < VADMIN_GROUP_STATE_DIGEST_OFFSET + sizeof(uint64_t) ?
		    0 : bytes[i];
		digest ^= byte;
		digest *= UINT64_C(1099511628211);
	}
	return (digest);
}

static void
vadmin_group_error(void *output, size_t output_length, size_t *written,
    uint16_t status, uint16_t qualifier)
{
	uint8_t *bytes;
	size_t initialized;

	bytes = output;
	initialized = MIN(output_length,
	    (size_t)BHYVE_VIRTIO_ADMIN_RESULT_HEADER_SIZE);
	memset(bytes, 0, initialized);
	if (initialized >= sizeof(uint16_t))
		le16enc(bytes, status);
	if (initialized >= 2 * sizeof(uint16_t))
		le16enc(bytes + 2, qualifier);
	*written = initialized;
}

int
virtio_admin_group_fabric_create(struct virtio_admin_group_fabric **result)
{
	struct virtio_admin_group_fabric *fabric;
	int error;

	if (result == NULL)
		return (EINVAL);
	fabric = calloc(1, sizeof(*fabric));
	if (fabric == NULL)
		return (ENOMEM);
	error = pthread_rwlock_init(&fabric->lock, NULL);
	if (error != 0) {
		free(fabric);
		return (error);
	}
	atomic_init(&fabric->sealed, false);
	*result = fabric;
	return (0);
}

void
virtio_admin_group_fabric_destroy(struct virtio_admin_group_fabric *fabric)
{

	if (fabric == NULL)
		return;
	/*
	 * A group command retains the fabric read lease through its end
	 * callback.  Drain that entire transaction before releasing command
	 * owners or the lock itself; waiting only for owner->active_commands
	 * would leave a window after the command handler returns but before
	 * the group callback and read unlock complete.
	 *
	 * As with the queue-bank destructor, the transport must already have
	 * stopped admission of new calls before destroying the object.
	 */
	pthread_rwlock_wrlock(&fabric->lock);
	for (uint8_t i = 0; i < fabric->count; i++)
		virtio_admin_owner_destroy(fabric->groups[i].owner);
	pthread_rwlock_unlock(&fabric->lock);
	pthread_rwlock_destroy(&fabric->lock);
	free(fabric);
}

int
virtio_admin_group_fabric_seal(struct virtio_admin_group_fabric *fabric)
{
	int error;

	if (fabric == NULL)
		return (EINVAL);
	if (atomic_load_explicit(&fabric->sealed, memory_order_acquire))
		return (0);
	pthread_rwlock_wrlock(&fabric->lock);
	error = 0;
	if (!atomic_load_explicit(&fabric->sealed, memory_order_relaxed)) {
		for (uint8_t i = 0; i < fabric->count; i++) {
			error = virtio_admin_owner_seal(fabric->groups[i].owner);
			if (error != 0)
				break;
		}
		if (error == 0)
			atomic_store_explicit(&fabric->sealed, true,
			    memory_order_release);
	}
	pthread_rwlock_unlock(&fabric->lock);
	return (error);
}

void
virtio_admin_group_fabric_reset(struct virtio_admin_group_fabric *fabric)
{

	if (fabric == NULL)
		return;
	pthread_rwlock_wrlock(&fabric->lock);
	for (uint8_t i = 0; i < fabric->count; i++) {
		virtio_admin_owner_reset(fabric->groups[i].owner);
		if (fabric->groups[i].config.reset != NULL)
			fabric->groups[i].config.reset(
			    fabric->groups[i].config.argument);
	}
	pthread_rwlock_unlock(&fabric->lock);
}

int
virtio_admin_group_register(struct virtio_admin_group_fabric *fabric,
    const struct virtio_admin_group_config *config,
    struct virtio_admin_owner **result)
{
	struct virtio_admin_owner *owner;
	int error;

	if (fabric == NULL || config == NULL || result == NULL)
		return (EINVAL);
	if (virtio_admin_group_snapshot_overlaps(fabric, config,
	    sizeof(*config)) ||
	    virtio_admin_group_snapshot_overlaps(fabric, result,
	    sizeof(*result)) ||
	    virtio_state_ranges_overlap(config, sizeof(*config), result,
	    sizeof(*result)))
		return (EINVAL);
	if (config->available == NULL || config->member_valid == NULL ||
	    ((config->begin == NULL) != (config->end == NULL)))
		return (EINVAL);
	error = virtio_admin_owner_create(&owner);
	if (error != 0)
		return (error);
	pthread_rwlock_wrlock(&fabric->lock);
	if (atomic_load_explicit(&fabric->sealed, memory_order_relaxed))
		error = EBUSY;
	else if (fabric->count >= BHYVE_VIRTIO_ADMIN_GROUP_MAX)
		error = ENOSPC;
	else if (vadmin_group_find(fabric, config->group_type) != NULL)
		error = EEXIST;
	else {
		fabric->groups[fabric->count++] = (struct vadmin_group) {
			.owner = owner,
			.config = *config,
		};
		*result = owner;
		owner = NULL;
		error = 0;
	}
	pthread_rwlock_unlock(&fabric->lock);
	virtio_admin_owner_destroy(owner);
	return (error);
}

struct virtio_admin_owner *
virtio_admin_group_owner(struct virtio_admin_group_fabric *fabric,
    uint16_t group_type)
{
	struct vadmin_group *group;
	struct virtio_admin_owner *owner;

	if (fabric == NULL)
		return (NULL);
	pthread_rwlock_rdlock(&fabric->lock);
	group = vadmin_group_find(fabric, group_type);
	owner = group == NULL ? NULL : group->owner;
	pthread_rwlock_unlock(&fabric->lock);
	return (owner);
}

int
virtio_admin_group_process(struct virtio_admin_group_fabric *fabric,
    const void *input, size_t input_length, void *output, size_t output_length,
    size_t *written)
{
	struct vadmin_group *group;
	uint8_t header[BHYVE_VIRTIO_ADMIN_HEADER_SIZE];
	uint16_t group_type, qualifier, status;
	int error;

	if (fabric == NULL || input == NULL || output == NULL ||
	    written == NULL)
		return (EINVAL);
	if (virtio_admin_group_snapshot_overlaps(fabric, input, input_length) ||
	    virtio_admin_group_snapshot_overlaps(fabric, output,
	    output_length) ||
	    virtio_admin_group_snapshot_overlaps(fabric, written,
	    sizeof(*written)) ||
	    virtio_state_ranges_overlap(input, input_length, output,
	    output_length) ||
	    virtio_state_ranges_overlap(input, input_length, written,
	    sizeof(*written)) ||
	    virtio_state_ranges_overlap(output, output_length, written,
	    sizeof(*written)))
		return (EINVAL);
	*written = 0;
	if (input_length == 0 || output_length == 0)
		return (EINVAL);
	error = virtio_admin_group_fabric_seal(fabric);
	if (error != 0)
		return (error);
	/*
	 * The group selector is part of the extensible administration command
	 * header.  Missing bytes read as zero, so even a one-byte readable
	 * part can address opcode zero in the self group.
	 */
	memset(header, 0, sizeof(header));
	memcpy(header, input, MIN(input_length, sizeof(header)));
	group_type = le16dec(header + 2);
	pthread_rwlock_rdlock(&fabric->lock);
	group = vadmin_group_find(fabric, group_type);
	if (group == NULL || !group->config.available(
	    group->config.argument)) {
		pthread_rwlock_unlock(&fabric->lock);
		vadmin_group_error(output, output_length, written,
		    BHYVE_VIRTIO_ADMIN_STATUS_EINVAL,
		    BHYVE_VIRTIO_ADMIN_QUALIFIER_INVALID_GROUP);
		return (0);
	}
	/*
	 * Opcode and immediately-observable member validation precede the
	 * external lifecycle lease.  Besides matching section 2.12.1.5, this
	 * prevents malformed commands from triggering begin/end side effects
	 * or being hidden by an unrelated transient lifecycle conflict.
	 * process_group() repeats the validation after begin() has stabilized
	 * dynamic membership.
	 */
	if (!virtio_admin_prevalidate_group(group->owner, group_type,
	    group->config.member_valid, group->config.argument, input,
	    input_length, &status, &qualifier)) {
		pthread_rwlock_unlock(&fabric->lock);
		vadmin_group_error(output, output_length, written, status,
		    qualifier);
		return (0);
	}
	qualifier = BHYVE_VIRTIO_ADMIN_QUALIFIER_INVALID_GROUP;
	if (group->config.begin != NULL &&
	    (error = group->config.begin(group->config.argument,
	    &qualifier)) != 0) {
		pthread_rwlock_unlock(&fabric->lock);
		/*
		 * A transient group-lifecycle conflict has no command side
		 * effects.  Report EAGAIN, the status for which the VirtIO
		 * administration specification recommends a driver retry,
		 * rather than pairing TRYAGAIN with the permanent EINVAL
		 * status.
		 */
		vadmin_group_error(output, output_length, written,
		    error == EAGAIN || error == EBUSY ?
		    BHYVE_VIRTIO_ADMIN_STATUS_EAGAIN :
		    BHYVE_VIRTIO_ADMIN_STATUS_EINVAL, qualifier);
		return (0);
	}
	error = virtio_admin_process_group(group->owner, group_type,
	    group->config.member_valid, group->config.argument, input,
	    input_length, output, output_length, written);
	if (group->config.end != NULL)
		group->config.end(group->config.argument);
	pthread_rwlock_unlock(&fabric->lock);
	return (error);
}

int
virtio_admin_group_snapshot_size(struct virtio_admin_group_fabric *fabric,
    size_t *result)
{

	if (fabric == NULL || result == NULL)
		return (EINVAL);
	if (virtio_admin_group_snapshot_overlaps(fabric, result,
	    sizeof(*result)))
		return (EINVAL);
	pthread_rwlock_rdlock(&fabric->lock);
	*result = BHYVE_VIRTIO_ADMIN_GROUP_STATE_HEADER_SIZE +
	    (size_t)fabric->count *
	    BHYVE_VIRTIO_ADMIN_GROUP_STATE_ENTRY_SIZE;
	pthread_rwlock_unlock(&fabric->lock);
	return (0);
}

int
virtio_admin_group_snapshot(struct virtio_admin_group_fabric *fabric,
    void *buffer, size_t length)
{
	uint8_t owner_state[BHYVE_VIRTIO_ADMIN_STATE_SIZE];
	uint8_t staging[BHYVE_VIRTIO_ADMIN_GROUP_STATE_HEADER_SIZE +
	    BHYVE_VIRTIO_ADMIN_GROUP_MAX *
	    BHYVE_VIRTIO_ADMIN_GROUP_STATE_ENTRY_SIZE];
	uint8_t *bytes;
	size_t cursor, required;

	if (fabric == NULL || buffer == NULL)
		return (EINVAL);
	if (virtio_admin_group_snapshot_overlaps(fabric, buffer, length))
		return (EINVAL);
	bytes = staging;
	pthread_rwlock_wrlock(&fabric->lock);
	required = BHYVE_VIRTIO_ADMIN_GROUP_STATE_HEADER_SIZE +
	    (size_t)fabric->count *
	    BHYVE_VIRTIO_ADMIN_GROUP_STATE_ENTRY_SIZE;
	if (length != required) {
		pthread_rwlock_unlock(&fabric->lock);
		return (EMSGSIZE);
	}
	memset(bytes, 0, length);
	le32enc(bytes, VADMIN_GROUP_STATE_MAGIC);
	le16enc(bytes + 4, VADMIN_GROUP_STATE_VERSION);
	le16enc(bytes + 6, BHYVE_VIRTIO_ADMIN_GROUP_STATE_HEADER_SIZE);
	le32enc(bytes + 8, (uint32_t)length);
	le16enc(bytes + 12, fabric->count);
	cursor = BHYVE_VIRTIO_ADMIN_GROUP_STATE_HEADER_SIZE;
	for (uint8_t i = 0; i < fabric->count; i++) {
		int error;

		error = virtio_admin_snapshot(fabric->groups[i].owner,
		    owner_state, sizeof(owner_state));
		if (error != 0) {
			pthread_rwlock_unlock(&fabric->lock);
			return (error);
		}
		le16enc(bytes + cursor, fabric->groups[i].config.group_type);
		le32enc(bytes + cursor + 4, sizeof(owner_state));
		memcpy(bytes + cursor + 8, owner_state, sizeof(owner_state));
		cursor += BHYVE_VIRTIO_ADMIN_GROUP_STATE_ENTRY_SIZE;
	}
	le64enc(bytes + VADMIN_GROUP_STATE_DIGEST_OFFSET,
	    vadmin_group_digest(bytes, length));
	memcpy(buffer, bytes, length);
	pthread_rwlock_unlock(&fabric->lock);
	return (0);
}

bool
virtio_admin_group_snapshot_overlaps(
    struct virtio_admin_group_fabric *fabric, const void *buffer, size_t length)
{
	bool overlaps;

	if (fabric == NULL)
		return (false);
	pthread_rwlock_rdlock(&fabric->lock);
	overlaps = virtio_state_ranges_overlap(buffer, length, fabric,
	    sizeof(*fabric));
	for (uint8_t i = 0; !overlaps && i < fabric->count; i++) {
		if (virtio_admin_snapshot_overlaps(fabric->groups[i].owner,
		    buffer, length))
			overlaps = true;
	}
	pthread_rwlock_unlock(&fabric->lock);
	return (overlaps);
}

static int
vadmin_group_restore(struct virtio_admin_group_fabric *fabric,
    const void *buffer, size_t length, bool publish)
{
	struct virtio_admin_owner *owners[BHYVE_VIRTIO_ADMIN_GROUP_MAX];
	const uint8_t *states[BHYVE_VIRTIO_ADMIN_GROUP_MAX];
	bool seen[BHYVE_VIRTIO_ADMIN_GROUP_MAX];
	const uint8_t *bytes;
	size_t cursor, expected;
	uint16_t count;
	int error;

	if (fabric == NULL || buffer == NULL)
		return (EINVAL);
	if (length < BHYVE_VIRTIO_ADMIN_GROUP_STATE_HEADER_SIZE ||
	    length > UINT32_MAX)
		return (EMSGSIZE);
	if (virtio_admin_group_snapshot_overlaps(fabric, buffer, length))
		return (EINVAL);
	bytes = buffer;
	if (le32dec(bytes) != VADMIN_GROUP_STATE_MAGIC ||
	    le16dec(bytes + 4) != VADMIN_GROUP_STATE_VERSION ||
	    le16dec(bytes + 6) !=
	    BHYVE_VIRTIO_ADMIN_GROUP_STATE_HEADER_SIZE ||
	    le32dec(bytes + 8) != length ||
	    le16dec(bytes + 14) != 0 ||
	    le64dec(bytes + 16) != 0 ||
	    le64dec(bytes + VADMIN_GROUP_STATE_DIGEST_OFFSET) !=
	    vadmin_group_digest(bytes, length))
		return (EPROTO);
	count = le16dec(bytes + 12);
	if (count > BHYVE_VIRTIO_ADMIN_GROUP_MAX)
		return (EPROTO);
	expected = BHYVE_VIRTIO_ADMIN_GROUP_STATE_HEADER_SIZE +
	    (size_t)count * BHYVE_VIRTIO_ADMIN_GROUP_STATE_ENTRY_SIZE;
	if (length != expected)
		return (EPROTO);

	memset(states, 0, sizeof(states));
	memset(seen, 0, sizeof(seen));
	pthread_rwlock_wrlock(&fabric->lock);
	if (count != fabric->count) {
		error = ENOTSUP;
		goto out;
	}
	cursor = BHYVE_VIRTIO_ADMIN_GROUP_STATE_HEADER_SIZE;
	for (uint16_t entry = 0; entry < count; entry++) {
		struct vadmin_group *group;
		size_t index;
		uint16_t group_type;

		group_type = le16dec(bytes + cursor);
		if (le16dec(bytes + cursor + 2) != 0 ||
		    le32dec(bytes + cursor + 4) !=
		    BHYVE_VIRTIO_ADMIN_STATE_SIZE ||
		    le64dec(bytes + cursor + 40) != 0) {
			error = EPROTO;
			goto out;
		}
		group = vadmin_group_find(fabric, group_type);
		if (group == NULL) {
			error = ENOTSUP;
			goto out;
		}
		index = (size_t)(group - fabric->groups);
		if (seen[index]) {
			error = EPROTO;
			goto out;
		}
		error = virtio_admin_restore_validate(group->owner,
		    bytes + cursor + 8, BHYVE_VIRTIO_ADMIN_STATE_SIZE);
		if (error != 0)
			goto out;
		seen[index] = true;
		states[index] = bytes + cursor + 8;
		cursor += BHYVE_VIRTIO_ADMIN_GROUP_STATE_ENTRY_SIZE;
	}
	for (uint8_t i = 0; i < fabric->count; i++) {
		if (!seen[i]) {
			error = ENOTSUP;
			goto out;
		}
		owners[i] = fabric->groups[i].owner;
	}
	if (publish)
		error = virtio_admin_restore_many(owners,
		    (const void *const *)states, fabric->count,
		    BHYVE_VIRTIO_ADMIN_STATE_SIZE);
	else
		error = 0;
out:
	pthread_rwlock_unlock(&fabric->lock);
	return (error);
}

int
virtio_admin_group_restore_validate(
    struct virtio_admin_group_fabric *fabric, const void *buffer,
    size_t length)
{

	return (vadmin_group_restore(fabric, buffer, length, false));
}

int
virtio_admin_group_restore(struct virtio_admin_group_fabric *fabric,
    const void *buffer, size_t length)
{

	return (vadmin_group_restore(fabric, buffer, length, true));
}
