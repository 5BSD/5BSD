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
#include "virtio_state_range.h"
#include "virtio_pci_modern_probes.h"

#define	VADMIN_STATE_MAGIC	0x314d4441U	/* "ADM1" */
#define	VADMIN_STATE_VERSION	1U
#define	VADMIN_STATE_DIGEST_OFFSET	24U
#define	VADMIN_BASE_COMMANDS	((UINT64_C(1) << \
    BHYVE_VIRTIO_ADMIN_CMD_LIST_QUERY) | (UINT64_C(1) << \
    BHYVE_VIRTIO_ADMIN_CMD_LIST_USE))

struct virtio_admin_owner {
	pthread_mutex_t mutex;
	pthread_cond_t quiesced;
	virtio_admin_command_cb handlers[64];
	void *handler_arguments[64];
	uint64_t supported_commands;
	uint64_t used_commands;
	uint64_t generation;
	size_t active_commands;
	bool resetting;
	bool sealed;
};

static bool
vadmin_owner_overlaps(struct virtio_admin_owner *owner, const void *buffer,
    size_t length)
{

	return (owner != NULL && virtio_state_ranges_overlap(owner,
	    sizeof(*owner), buffer, length));
}

static uint64_t
vadmin_digest(const uint8_t *bytes, size_t length)
{
	uint64_t digest;

	digest = UINT64_C(14695981039346656037);
	for (size_t i = 0; i < length; i++) {
		uint8_t byte;

		byte = i >= VADMIN_STATE_DIGEST_OFFSET &&
		    i < VADMIN_STATE_DIGEST_OFFSET + sizeof(uint64_t) ?
		    0 : bytes[i];
		digest ^= byte;
		digest *= UINT64_C(1099511628211);
	}
	return (digest);
}

static void
vadmin_result(uint8_t *output, size_t output_length, uint16_t status,
    uint16_t qualifier)
{
	size_t initialized;

	initialized = MIN(output_length,
	    (size_t)BHYVE_VIRTIO_ADMIN_RESULT_HEADER_SIZE);
	memset(output, 0, initialized);
	if (initialized >= sizeof(uint16_t))
		le16enc(output, status);
	if (initialized >= 2 * sizeof(uint16_t))
		le16enc(output + sizeof(uint16_t), qualifier);
}

uint16_t
virtio_admin_status_from_errno(int error)
{

	switch (error) {
	case 0:
		return (BHYVE_VIRTIO_ADMIN_STATUS_OK);
	case ENXIO:
		return (BHYVE_VIRTIO_ADMIN_STATUS_ENXIO);
	case EAGAIN:
		return (BHYVE_VIRTIO_ADMIN_STATUS_EAGAIN);
	case ENOMEM:
		return (BHYVE_VIRTIO_ADMIN_STATUS_ENOMEM);
	case EBUSY:
		return (BHYVE_VIRTIO_ADMIN_STATUS_EBUSY);
	case EEXIST:
		return (BHYVE_VIRTIO_ADMIN_STATUS_EEXIST);
	case EINVAL:
		return (BHYVE_VIRTIO_ADMIN_STATUS_EINVAL);
	case ENOSPC:
		return (BHYVE_VIRTIO_ADMIN_STATUS_ENOSPC);
	default:
		/*
		 * Host errno values are not a VirtIO ABI.  Unknown implementation
		 * failures are invalid commands at the portable administration
		 * boundary; the command-specific qualifier retains the useful
		 * low-level classification.
		 */
		return (BHYVE_VIRTIO_ADMIN_STATUS_EINVAL);
	}
}

static bool
vadmin_status_valid(uint16_t status)
{

	switch (status) {
	case BHYVE_VIRTIO_ADMIN_STATUS_OK:
	case BHYVE_VIRTIO_ADMIN_STATUS_ENXIO:
	case BHYVE_VIRTIO_ADMIN_STATUS_EAGAIN:
	case BHYVE_VIRTIO_ADMIN_STATUS_ENOMEM:
	case BHYVE_VIRTIO_ADMIN_STATUS_EBUSY:
	case BHYVE_VIRTIO_ADMIN_STATUS_EEXIST:
	case BHYVE_VIRTIO_ADMIN_STATUS_EINVAL:
	case BHYVE_VIRTIO_ADMIN_STATUS_ENOSPC:
		return (true);
	default:
		return (false);
	}
}

static bool
vadmin_qualifier_valid(uint16_t qualifier)
{

	return (qualifier <= BHYVE_VIRTIO_ADMIN_QUALIFIER_TRYAGAIN);
}

int
virtio_admin_owner_create(struct virtio_admin_owner **result)
{
	struct virtio_admin_owner *owner;
	int error;

	if (result == NULL)
		return (EINVAL);
	owner = calloc(1, sizeof(*owner));
	if (owner == NULL)
		return (ENOMEM);
	error = pthread_mutex_init(&owner->mutex, NULL);
	if (error != 0) {
		free(owner);
		return (error);
	}
	error = pthread_cond_init(&owner->quiesced, NULL);
	if (error != 0) {
		pthread_mutex_destroy(&owner->mutex);
		free(owner);
		return (error);
	}
	/*
	 * VirtIO 1.4 section 2.12.1.1 requires these two commands to be
	 * assumed in use after reset, before the first LIST_USE.
	 */
	owner->used_commands = VADMIN_BASE_COMMANDS;
	owner->supported_commands = VADMIN_BASE_COMMANDS;
	*result = owner;
	return (0);
}

int
virtio_admin_owner_register_command(struct virtio_admin_owner *owner,
    uint16_t opcode, virtio_admin_command_cb handler, void *argument)
{
	const struct virtio_admin_command_registration registration = {
		.opcode = opcode,
		.handler = handler,
		.argument = argument,
	};

	return (virtio_admin_owner_register_commands(owner, &registration, 1));
}

int
virtio_admin_owner_register_commands(struct virtio_admin_owner *owner,
    const struct virtio_admin_command_registration *registrations,
    size_t count)
{
	uint64_t additions;
	int error;

	if (owner == NULL || registrations == NULL || count == 0 || count > 62)
		return (EINVAL);
	if (count > SIZE_MAX / sizeof(*registrations) ||
	    vadmin_owner_overlaps(owner, registrations,
	    count * sizeof(*registrations)))
		return (EINVAL);
	additions = 0;
	for (size_t i = 0; i < count; i++) {
		uint16_t opcode;
		uint64_t bit;

		opcode = registrations[i].opcode;
		if (registrations[i].handler == NULL ||
		    opcode <= BHYVE_VIRTIO_ADMIN_CMD_LIST_USE ||
		    opcode == BHYVE_VIRTIO_ADMIN_CMD_RESERVED_0012 ||
		    opcode >= 64)
			return (EINVAL);
		bit = UINT64_C(1) << opcode;
		if ((additions & bit) != 0)
			return (EEXIST);
		additions |= bit;
	}
	pthread_mutex_lock(&owner->mutex);
	if (owner->sealed) {
		error = EBUSY;
	} else if ((owner->supported_commands & additions) != 0) {
		error = EEXIST;
	} else {
		for (size_t i = 0; i < count; i++) {
			uint16_t opcode;

			opcode = registrations[i].opcode;
			owner->handlers[opcode] = registrations[i].handler;
			owner->handler_arguments[opcode] =
			    registrations[i].argument;
		}
		/*
		 * VirtIO 1.4 section 2.12.1.5 forbids the supported command
		 * list from shrinking.  Registration is therefore monotonic;
		 * command removal requires destroying the owner.
		 */
		owner->supported_commands |= additions;
		error = 0;
	}
	pthread_mutex_unlock(&owner->mutex);
	return (error);
}

int
virtio_admin_owner_seal(struct virtio_admin_owner *owner)
{

	if (owner == NULL)
		return (EINVAL);
	pthread_mutex_lock(&owner->mutex);
	owner->sealed = true;
	pthread_mutex_unlock(&owner->mutex);
	return (0);
}

void
virtio_admin_owner_destroy(struct virtio_admin_owner *owner)
{

	if (owner == NULL)
		return;
	/*
	 * Queue owners stop admission before destruction.  Still drain a
	 * command which was already dispatched so callback arguments may be
	 * released immediately after this function returns.
	 */
	pthread_mutex_lock(&owner->mutex);
	owner->resetting = true;
	/*
	 * Destruction and reset both close command admission before draining
	 * handlers.  Wake observers after publishing that state transition:
	 * otherwise a waiter which observed !resetting can sleep indefinitely
	 * while destroy() waits for the already-active callback to retire.
	 */
	pthread_cond_broadcast(&owner->quiesced);
	while (owner->active_commands != 0)
		pthread_cond_wait(&owner->quiesced, &owner->mutex);
	pthread_mutex_unlock(&owner->mutex);
	pthread_cond_destroy(&owner->quiesced);
	pthread_mutex_destroy(&owner->mutex);
	free(owner);
}

void
virtio_admin_owner_reset(struct virtio_admin_owner *owner)
{

	if (owner == NULL)
		return;
	pthread_mutex_lock(&owner->mutex);
	owner->resetting = true;
	pthread_cond_broadcast(&owner->quiesced);
	while (owner->active_commands != 0)
		pthread_cond_wait(&owner->quiesced, &owner->mutex);
	owner->used_commands = VADMIN_BASE_COMMANDS;
	owner->generation++;
	owner->resetting = false;
	pthread_cond_broadcast(&owner->quiesced);
	pthread_mutex_unlock(&owner->mutex);
}

static bool
vadmin_self_member(void *argument, uint64_t member_id)
{

	(void)argument;
	return (member_id == 0);
}

struct vadmin_command_header {
	uint64_t group_member_id;
	uint16_t group_type;
	uint16_t opcode;
};

static void
vadmin_decode_command_header(const void *input, size_t input_length,
    struct vadmin_command_header *decoded)
{
	uint8_t header[BHYVE_VIRTIO_ADMIN_HEADER_SIZE];

	memset(header, 0, sizeof(header));
	memcpy(header, input, MIN(input_length, sizeof(header)));
	decoded->opcode = le16dec(header);
	decoded->group_type = le16dec(header + sizeof(uint16_t));
	decoded->group_member_id = le64dec(header + 16);
}

static bool
vadmin_validate_command_locked(struct virtio_admin_owner *owner,
    uint16_t expected_group, virtio_admin_member_validate_cb member_validate,
    void *member_argument, const struct vadmin_command_header *header,
    uint16_t *status, uint16_t *qualifier)
{

	if (header->group_type != expected_group) {
		*status = BHYVE_VIRTIO_ADMIN_STATUS_EINVAL;
		*qualifier = BHYVE_VIRTIO_ADMIN_QUALIFIER_INVALID_GROUP;
	} else if (owner->resetting) {
		/*
		 * Reset closes admission for every opcode, including one the
		 * driver disabled with LIST_USE.  A retryable status must have
		 * no side effects.
		 */
		*status = BHYVE_VIRTIO_ADMIN_STATUS_EAGAIN;
		*qualifier = BHYVE_VIRTIO_ADMIN_QUALIFIER_TRYAGAIN;
	} else if (header->opcode >= 64 ||
	    (owner->used_commands & (UINT64_C(1) << header->opcode)) == 0) {
		*status = BHYVE_VIRTIO_ADMIN_STATUS_EINVAL;
		*qualifier = BHYVE_VIRTIO_ADMIN_QUALIFIER_INVALID_OPCODE;
	} else if (header->opcode != BHYVE_VIRTIO_ADMIN_CMD_LIST_QUERY &&
	    header->opcode != BHYVE_VIRTIO_ADMIN_CMD_LIST_USE &&
	    !member_validate(member_argument, header->group_member_id)) {
		/*
		 * group_member_id is unused by LIST_QUERY and LIST_USE and is
		 * therefore ignored for those commands.
		 */
		*status = BHYVE_VIRTIO_ADMIN_STATUS_EINVAL;
		*qualifier = BHYVE_VIRTIO_ADMIN_QUALIFIER_INVALID_MEMBER;
	} else {
		*status = BHYVE_VIRTIO_ADMIN_STATUS_OK;
		*qualifier = BHYVE_VIRTIO_ADMIN_QUALIFIER_OK;
		return (true);
	}
	return (false);
}

bool
virtio_admin_prevalidate_group(struct virtio_admin_owner *owner,
    uint16_t expected_group, virtio_admin_member_validate_cb member_validate,
    void *member_argument, const void *input, size_t input_length,
    uint16_t *status, uint16_t *qualifier)
{
	struct vadmin_command_header header;
	bool valid;
	bool aliases;

	aliases = false;
	if (owner != NULL) {
		aliases = (status != NULL && vadmin_owner_overlaps(owner, status,
		    sizeof(*status))) ||
		    (qualifier != NULL && vadmin_owner_overlaps(owner, qualifier,
		    sizeof(*qualifier)));
	}
	if (!aliases && input != NULL) {
		aliases = (status != NULL && virtio_state_ranges_overlap(input,
		    input_length, status, sizeof(*status))) ||
		    (qualifier != NULL && virtio_state_ranges_overlap(input,
		    input_length, qualifier, sizeof(*qualifier)));
	}
	if (!aliases && status != NULL && qualifier != NULL)
		aliases = virtio_state_ranges_overlap(status, sizeof(*status),
		    qualifier, sizeof(*qualifier));
	if (aliases)
		return (false);

	if (owner == NULL || member_validate == NULL || input == NULL ||
	    input_length == 0 || status == NULL || qualifier == NULL) {
		if (status != NULL)
			*status = BHYVE_VIRTIO_ADMIN_STATUS_EINVAL;
		if (qualifier != NULL)
			*qualifier =
			    BHYVE_VIRTIO_ADMIN_QUALIFIER_INVALID_COMMAND;
		return (false);
	}
	vadmin_decode_command_header(input, input_length, &header);
	pthread_mutex_lock(&owner->mutex);
	valid = vadmin_validate_command_locked(owner, expected_group,
	    member_validate, member_argument, &header, status, qualifier);
	pthread_mutex_unlock(&owner->mutex);
	return (valid);
}

int
virtio_admin_process_group(struct virtio_admin_owner *owner,
    uint16_t expected_group, virtio_admin_member_validate_cb member_validate,
    void *member_argument, const void *input, size_t input_length, void *output,
    size_t output_length, size_t *written)
{
	struct vadmin_command_header header;
	const uint8_t *input_bytes;
	uint8_t *output_bytes;
	struct virtio_admin_command_result command_result;
	virtio_admin_command_cb handler;
	void *handler_argument;
	uint64_t group_member_id, requested, supported_commands;
	uint16_t group_type, opcode, qualifier, status;
	size_t result_length;

	if (owner == NULL || member_validate == NULL || input == NULL ||
	    output == NULL || written == NULL)
		return (EINVAL);
	if (vadmin_owner_overlaps(owner, input, input_length) ||
	    vadmin_owner_overlaps(owner, output, output_length) ||
	    vadmin_owner_overlaps(owner, written, sizeof(*written)) ||
	    virtio_state_ranges_overlap(input, input_length, output,
	    output_length) ||
	    virtio_state_ranges_overlap(input, input_length, written,
	    sizeof(*written)) ||
	    virtio_state_ranges_overlap(output, output_length, written,
	    sizeof(*written)))
		return (EINVAL);
	*written = 0;
	/*
	 * VirtIO 1.4 section 2.13.1 requires shorter command structures to
	 * be accepted: missing device-readable bytes are zero and
	 * device-writable bytes are silently truncated.  A zero-length part
	 * is still invalid under the driver requirements in section 2.13.2.
	 */
	if (input_length == 0 || output_length == 0)
		return (EINVAL);
	/* First command execution permanently freezes the supported list. */
	if (virtio_admin_owner_seal(owner) != 0)
		return (EINVAL);

	vadmin_decode_command_header(input, input_length, &header);
	input_bytes = input;
	output_bytes = output;
	opcode = header.opcode;
	group_type = header.group_type;
	group_member_id = header.group_member_id;
	status = BHYVE_VIRTIO_ADMIN_STATUS_OK;
	qualifier = BHYVE_VIRTIO_ADMIN_QUALIFIER_OK;
	result_length = BHYVE_VIRTIO_ADMIN_RESULT_HEADER_SIZE;
	handler = NULL;
	handler_argument = NULL;

	pthread_mutex_lock(&owner->mutex);
	supported_commands = owner->supported_commands;
	if (!vadmin_validate_command_locked(owner, expected_group,
	    member_validate, member_argument, &header, &status, &qualifier)) {
		/* Validation already selected the normative error precedence. */
	} else if (opcode == BHYVE_VIRTIO_ADMIN_CMD_LIST_QUERY) {
		result_length += BHYVE_VIRTIO_ADMIN_LIST_SIZE;
	} else if (opcode == BHYVE_VIRTIO_ADMIN_CMD_LIST_USE) {
		uint8_t requested_bytes[sizeof(uint64_t)];

		memset(requested_bytes, 0, sizeof(requested_bytes));
		if (input_length > BHYVE_VIRTIO_ADMIN_HEADER_SIZE) {
			memcpy(requested_bytes,
			    input_bytes + BHYVE_VIRTIO_ADMIN_HEADER_SIZE,
			    MIN(input_length - BHYVE_VIRTIO_ADMIN_HEADER_SIZE,
			    sizeof(requested_bytes)));
		}
		requested = le64dec(requested_bytes);
		/*
		 * LIST_USE selects an arbitrary subset of LIST_QUERY.  In
		 * particular, the driver is explicitly allowed to disable
		 * LIST_QUERY and LIST_USE themselves by clearing their bits.
		 * Bytes beyond the specified 8-byte command-specific field are
		 * ignored as required by VirtIO 1.4 section 2.13.1.
		 */
		if ((requested & ~supported_commands) != 0) {
			status = BHYVE_VIRTIO_ADMIN_STATUS_EINVAL;
			qualifier = BHYVE_VIRTIO_ADMIN_QUALIFIER_INVALID_FIELD;
		} else {
			owner->used_commands = requested;
			owner->generation++;
		}
	} else {
		handler = owner->handlers[opcode];
		handler_argument = owner->handler_arguments[opcode];
		owner->active_commands++;
	}
	pthread_mutex_unlock(&owner->mutex);

	if (handler != NULL) {
		command_result = (struct virtio_admin_command_result) {
			.status = BHYVE_VIRTIO_ADMIN_STATUS_OK,
			.qualifier = BHYVE_VIRTIO_ADMIN_QUALIFIER_OK,
			.result_length = 0,
		};
		handler(handler_argument, group_member_id,
		    input_length > BHYVE_VIRTIO_ADMIN_HEADER_SIZE ?
		    input_bytes + BHYVE_VIRTIO_ADMIN_HEADER_SIZE : NULL,
		    input_length > BHYVE_VIRTIO_ADMIN_HEADER_SIZE ?
		    input_length - BHYVE_VIRTIO_ADMIN_HEADER_SIZE : 0,
		    output_length > BHYVE_VIRTIO_ADMIN_RESULT_HEADER_SIZE ?
		    output_bytes + BHYVE_VIRTIO_ADMIN_RESULT_HEADER_SIZE : NULL,
		    output_length > BHYVE_VIRTIO_ADMIN_RESULT_HEADER_SIZE ?
		    output_length - BHYVE_VIRTIO_ADMIN_RESULT_HEADER_SIZE : 0,
		    &command_result);
		pthread_mutex_lock(&owner->mutex);
		owner->active_commands--;
		if (owner->active_commands == 0)
			pthread_cond_broadcast(&owner->quiesced);
		pthread_mutex_unlock(&owner->mutex);
		status = command_result.status;
		qualifier = command_result.qualifier;
		/*
		 * A command adapter must not extend the portable administration
		 * ABI with a host errno or a private status value.
		 */
		if (!vadmin_status_valid(status)) {
			status = BHYVE_VIRTIO_ADMIN_STATUS_EINVAL;
			qualifier =
			    BHYVE_VIRTIO_ADMIN_QUALIFIER_INVALID_COMMAND;
		} else if (!vadmin_qualifier_valid(qualifier)) {
			qualifier =
			    BHYVE_VIRTIO_ADMIN_QUALIFIER_INVALID_COMMAND;
		}
		/*
		 * status_qualifier is reserved and must be zero on successful
		 * completion.  Keep a defective command implementation from
		 * leaking a reserved value onto the administration wire.
		 */
		if (status == BHYVE_VIRTIO_ADMIN_STATUS_OK)
			qualifier = BHYVE_VIRTIO_ADMIN_QUALIFIER_OK;
		if (command_result.result_length > SIZE_MAX -
		    BHYVE_VIRTIO_ADMIN_RESULT_HEADER_SIZE) {
			VIRTIO_PROBE_ADMIN_COMMAND(group_type, opcode,
			    group_member_id, status, qualifier);
			return (EOVERFLOW);
		}
		result_length = BHYVE_VIRTIO_ADMIN_RESULT_HEADER_SIZE +
		    command_result.result_length;
	}
	vadmin_result(output_bytes, output_length, status, qualifier);
	if (status == BHYVE_VIRTIO_ADMIN_STATUS_OK &&
	    opcode == BHYVE_VIRTIO_ADMIN_CMD_LIST_QUERY &&
	    output_length > BHYVE_VIRTIO_ADMIN_RESULT_HEADER_SIZE) {
		uint8_t list_bytes[BHYVE_VIRTIO_ADMIN_LIST_SIZE];
		size_t list_length;

		list_length = MIN(output_length -
		    BHYVE_VIRTIO_ADMIN_RESULT_HEADER_SIZE,
		    (size_t)BHYVE_VIRTIO_ADMIN_LIST_SIZE);
		memset(output_bytes + BHYVE_VIRTIO_ADMIN_RESULT_HEADER_SIZE, 0,
		    list_length);
		le64enc(list_bytes, supported_commands);
		memcpy(output_bytes + BHYVE_VIRTIO_ADMIN_RESULT_HEADER_SIZE,
		    list_bytes, list_length);
	}
	*written = MIN(output_length, result_length);
	VIRTIO_PROBE_ADMIN_COMMAND(group_type, opcode, group_member_id, status,
	    qualifier);
	return (0);
}

int
virtio_admin_process(struct virtio_admin_owner *owner, const void *input,
    size_t input_length, void *output, size_t output_length, size_t *written)
{

	return (virtio_admin_process_group(owner,
	    BHYVE_VIRTIO_ADMIN_GROUP_SELF, vadmin_self_member, NULL, input,
	    input_length, output, output_length, written));
}

int
virtio_admin_snapshot(struct virtio_admin_owner *owner, void *buffer,
    size_t length)
{
	uint8_t *bytes;

	if (owner == NULL || buffer == NULL)
		return (EINVAL);
	if (length != BHYVE_VIRTIO_ADMIN_STATE_SIZE)
		return (EMSGSIZE);
	if (virtio_admin_snapshot_overlaps(owner, buffer, length))
		return (EINVAL);
	bytes = buffer;
	pthread_mutex_lock(&owner->mutex);
	if (owner->resetting || owner->active_commands != 0) {
		pthread_mutex_unlock(&owner->mutex);
		return (EBUSY);
	}
	memset(bytes, 0, length);
	le32enc(bytes, VADMIN_STATE_MAGIC);
	le16enc(bytes + 4, VADMIN_STATE_VERSION);
	le16enc(bytes + 6, BHYVE_VIRTIO_ADMIN_STATE_SIZE);
	le64enc(bytes + 8, owner->used_commands);
	le64enc(bytes + 16, owner->generation);
	le64enc(bytes + VADMIN_STATE_DIGEST_OFFSET,
	    vadmin_digest(bytes, length));
	pthread_mutex_unlock(&owner->mutex);
	return (0);
}

bool
virtio_admin_snapshot_overlaps(struct virtio_admin_owner *owner,
    const void *buffer, size_t length)
{

	return (owner != NULL &&
	    virtio_state_ranges_overlap(buffer, length, owner, sizeof(*owner)));
}

int
virtio_admin_restore_validate(struct virtio_admin_owner *owner,
    const void *buffer,
    size_t length)
{
	const uint8_t *bytes;
	uint64_t used_commands;

	if (owner == NULL || buffer == NULL)
		return (EINVAL);
	if (length != BHYVE_VIRTIO_ADMIN_STATE_SIZE)
		return (EMSGSIZE);
	if (virtio_admin_snapshot_overlaps(owner, buffer, length))
		return (EINVAL);
	bytes = buffer;
	if (le32dec(bytes) != VADMIN_STATE_MAGIC ||
	    le16dec(bytes + 4) != VADMIN_STATE_VERSION ||
	    le16dec(bytes + 6) != BHYVE_VIRTIO_ADMIN_STATE_SIZE ||
	    le64dec(bytes + VADMIN_STATE_DIGEST_OFFSET) !=
	    vadmin_digest(bytes, length))
		return (EPROTO);
	used_commands = le64dec(bytes + 8);
	pthread_mutex_lock(&owner->mutex);
	if ((used_commands & ~owner->supported_commands) != 0) {
		pthread_mutex_unlock(&owner->mutex);
		return (ENOTSUP);
	}
	pthread_mutex_unlock(&owner->mutex);
	return (0);
}

/*
 * Clang's thread-safety analysis cannot express a dynamically sorted set of
 * mutexes.  Keep that exception confined to these two balanced helpers; the
 * caller still holds every owner lock across the complete validate/publish
 * transaction.
 */
static void
vadmin_restore_lock_many(struct virtio_admin_owner *const *owners,
    const size_t *order, size_t count) __no_lock_analysis;
static void
vadmin_restore_lock_many(struct virtio_admin_owner *const *owners,
    const size_t *order, size_t count)
{

	for (size_t i = 0; i < count; i++)
		pthread_mutex_lock(&owners[order[i]]->mutex);
}

static void
vadmin_restore_unlock_many(struct virtio_admin_owner *const *owners,
    const size_t *order, size_t count) __no_lock_analysis;
static void
vadmin_restore_unlock_many(struct virtio_admin_owner *const *owners,
    const size_t *order, size_t count)
{

	while (count != 0)
		pthread_mutex_unlock(&owners[order[--count]]->mutex);
}

int
virtio_admin_restore_many(struct virtio_admin_owner *const *owners,
    const void *const *buffers, size_t count, size_t length)
{
	const uint8_t *bytes;
	size_t buffers_size, owners_size;
	size_t *order;
	int error;

	if (owners == NULL || buffers == NULL || count == 0)
		return (EINVAL);
	if (length != BHYVE_VIRTIO_ADMIN_STATE_SIZE)
		return (EMSGSIZE);
	if (count > SIZE_MAX / sizeof(*order) ||
	    count > SIZE_MAX / sizeof(*owners) ||
	    count > SIZE_MAX / sizeof(*buffers))
		return (EOVERFLOW);
	owners_size = count * sizeof(*owners);
	buffers_size = count * sizeof(*buffers);
	for (size_t i = 0; i < count; i++) {
		if (owners[i] == NULL || buffers[i] == NULL)
			return (EINVAL);
		/*
		 * The pointer vectors remain live through publication and ordered
		 * unlock.  If either vector occupies a destination owner, publishing
		 * used_commands or generation can rewrite a later pointer (or the
		 * pointer used to unlock this owner) after validation.  Reject that
		 * ownership violation before acquiring any mutex.
		 */
		if (vadmin_owner_overlaps(owners[i], owners, owners_size) ||
		    vadmin_owner_overlaps(owners[i], buffers, buffers_size))
			return (EINVAL);
		/*
		 * Publication writes every owner after all records are parsed.  A
		 * source record must therefore be disjoint from every destination,
		 * not merely the owner at the same array index; otherwise publishing
		 * an earlier owner can rewrite a later record mid-transaction.
		 */
		for (size_t j = 0; j < count; j++) {
			if (owners[j] == NULL ||
			    virtio_admin_snapshot_overlaps(owners[j], buffers[i],
			    length))
				return (EINVAL);
		}
		for (size_t j = 0; j < i; j++) {
			if (owners[i] == owners[j])
				return (EINVAL);
		}
		bytes = buffers[i];
		if (le32dec(bytes) != VADMIN_STATE_MAGIC ||
		    le16dec(bytes + 4) != VADMIN_STATE_VERSION ||
		    le16dec(bytes + 6) != BHYVE_VIRTIO_ADMIN_STATE_SIZE ||
		    le64dec(bytes + VADMIN_STATE_DIGEST_OFFSET) !=
		    vadmin_digest(bytes, length))
			return (EPROTO);
	}

	order = malloc(count * sizeof(*order));
	if (order == NULL)
		return (ENOMEM);
	for (size_t i = 0; i < count; i++) {
		size_t j;

		order[i] = i;
		for (j = i; j > 0 &&
		    (uintptr_t)owners[order[j - 1]] >
		    (uintptr_t)owners[order[j]]; j--) {
			size_t temporary;

			temporary = order[j - 1];
			order[j - 1] = order[j];
			order[j] = temporary;
		}
	}
	vadmin_restore_lock_many(owners, order, count);
	for (size_t i = 0; i < count; i++) {
		bytes = buffers[i];
		if ((le64dec(bytes + 8) &
		    ~owners[i]->supported_commands) != 0) {
			error = ENOTSUP;
			goto out;
		}
		if (owners[i]->resetting || owners[i]->active_commands != 0) {
			error = EBUSY;
			goto out;
		}
	}
	for (size_t i = 0; i < count; i++) {
		bytes = buffers[i];
		owners[i]->used_commands = le64dec(bytes + 8);
		owners[i]->generation = le64dec(bytes + 16);
	}
	error = 0;
out:
	vadmin_restore_unlock_many(owners, order, count);
	free(order);
	return (error);
}

int
virtio_admin_restore(struct virtio_admin_owner *owner, const void *buffer,
    size_t length)
{
	struct virtio_admin_owner *owners[] = { owner };
	const void *buffers[] = { buffer };

	return (virtio_admin_restore_many(owners, buffers, nitems(owners),
	    length));
}
