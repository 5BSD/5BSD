/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/endian.h>

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "virtio_fs_backend.h"

#define	VFSB_OFF_MAGIC		0U
#define	VFSB_OFF_VERSION	4U
#define	VFSB_OFF_TYPE		6U
#define	VFSB_OFF_HEADER_SIZE	8U
#define	VFSB_OFF_FLAGS		10U
#define	VFSB_OFF_PAYLOAD_LEN	12U
#define	VFSB_OFF_REQUEST_ID	16U
#define	VFSB_OFF_INCARNATION	24U
#define	VFSB_OFF_STATUS		32U
#define	VFSB_OFF_RESERVED	36U

static bool
virtio_fs_backend_type_valid(enum virtio_fs_backend_message_type type)
{

	return (type >= VIRTIO_FS_BACKEND_HELLO &&
	    type <= VIRTIO_FS_BACKEND_NOTIFICATION);
}

static bool
virtio_fs_backend_type_is_reply(enum virtio_fs_backend_message_type type)
{

	return (type == VIRTIO_FS_BACKEND_HELLO_REPLY ||
	    type == VIRTIO_FS_BACKEND_RESPONSE ||
	    type == VIRTIO_FS_BACKEND_CANCEL_REPLY ||
	    type == VIRTIO_FS_BACKEND_QUIESCE_REPLY ||
	    type == VIRTIO_FS_BACKEND_THAW_REPLY ||
	    type == VIRTIO_FS_BACKEND_SHUTDOWN_REPLY);
}

static bool
virtio_fs_backend_type_allows_noreply(
    enum virtio_fs_backend_message_type type)
{

	return (type == VIRTIO_FS_BACKEND_REQUEST);
}

static int
virtio_fs_backend_header_validate(
    const struct virtio_fs_backend_header *header)
{
	uint16_t allowed_flags;
	bool control_id;

	if (header == NULL || !virtio_fs_backend_type_valid(header->type) ||
	    header->version != VIRTIO_FS_BACKEND_VERSION ||
	    (header->request_id == 0 &&
	    header->type != VIRTIO_FS_BACKEND_NOTIFICATION) ||
	    header->payload_len > VIRTIO_FS_BACKEND_MAX_FRAME)
		return (EINVAL);
	control_id = (header->request_id &
	    VIRTIO_FS_BACKEND_CONTROL_ID_BIT) != 0;
	if ((header->type == VIRTIO_FS_BACKEND_REQUEST ||
	    header->type == VIRTIO_FS_BACKEND_RESPONSE ||
	    header->type == VIRTIO_FS_BACKEND_CANCEL ||
	    header->type == VIRTIO_FS_BACKEND_CANCEL_REPLY ||
	    header->type == VIRTIO_FS_BACKEND_HELLO ||
	    header->type == VIRTIO_FS_BACKEND_HELLO_REPLY) && control_id)
		return (EINVAL);
	if ((header->type == VIRTIO_FS_BACKEND_QUIESCE ||
	    header->type == VIRTIO_FS_BACKEND_QUIESCE_REPLY ||
	    header->type == VIRTIO_FS_BACKEND_THAW ||
	    header->type == VIRTIO_FS_BACKEND_THAW_REPLY ||
	    header->type == VIRTIO_FS_BACKEND_SHUTDOWN ||
	    header->type == VIRTIO_FS_BACKEND_SHUTDOWN_REPLY) && !control_id)
		return (EINVAL);
	if (header->type == VIRTIO_FS_BACKEND_NOTIFICATION &&
	    (header->request_id != 0 || control_id))
		return (EINVAL);
	allowed_flags = virtio_fs_backend_type_allows_noreply(header->type) ?
	    VIRTIO_FS_BACKEND_MSG_F_NOREPLY : 0;
	if ((header->flags & ~allowed_flags) != 0)
		return (EINVAL);
	if ((header->type == VIRTIO_FS_BACKEND_HELLO ||
	    header->type == VIRTIO_FS_BACKEND_HELLO_REPLY) ?
	    header->incarnation != 0 : header->incarnation == 0)
		return (EINVAL);
	if ((!virtio_fs_backend_type_is_reply(header->type) &&
	    header->status != 0) ||
	    (virtio_fs_backend_type_is_reply(header->type) &&
	    header->status > 0))
		return (EINVAL);
	if (header->type == VIRTIO_FS_BACKEND_HELLO &&
	    header->payload_len != VIRTIO_FS_BACKEND_HELLO_SIZE)
		return (EINVAL);
	if (header->type == VIRTIO_FS_BACKEND_HELLO_REPLY &&
	    header->payload_len != (header->status == 0 ?
	    VIRTIO_FS_BACKEND_HELLO_SIZE : 0))
		return (EINVAL);
	if (header->type == VIRTIO_FS_BACKEND_RESPONSE &&
	    header->status < 0 && header->payload_len != 0)
		return (EINVAL);
	if ((header->type == VIRTIO_FS_BACKEND_QUIESCE ||
	    header->type == VIRTIO_FS_BACKEND_THAW_REPLY ||
	    header->type == VIRTIO_FS_BACKEND_SHUTDOWN ||
	    header->type == VIRTIO_FS_BACKEND_SHUTDOWN_REPLY ||
	    header->type == VIRTIO_FS_BACKEND_CANCEL ||
	    header->type == VIRTIO_FS_BACKEND_CANCEL_REPLY) &&
	    header->payload_len != 0)
		return (EINVAL);
	if (header->type == VIRTIO_FS_BACKEND_QUIESCE_REPLY &&
	    header->status != 0 && header->payload_len != 0)
		return (EINVAL);
	if (header->type == VIRTIO_FS_BACKEND_RESPONSE &&
	    (header->flags & VIRTIO_FS_BACKEND_MSG_F_NOREPLY) != 0)
		return (EINVAL);
	if (header->type == VIRTIO_FS_BACKEND_NOTIFICATION &&
	    header->payload_len == 0)
		return (EINVAL);
	return (0);
}

int
virtio_fs_backend_header_encode(
    const struct virtio_fs_backend_header *header,
    uint8_t output[VIRTIO_FS_BACKEND_HEADER_SIZE])
{
	int error;

	if (output == NULL)
		return (EINVAL);
	error = virtio_fs_backend_header_validate(header);
	if (error != 0)
		return (error);
	memset(output, 0, VIRTIO_FS_BACKEND_HEADER_SIZE);
	le32enc(output + VFSB_OFF_MAGIC, VIRTIO_FS_BACKEND_MAGIC);
	le16enc(output + VFSB_OFF_VERSION, header->version);
	le16enc(output + VFSB_OFF_TYPE, header->type);
	le16enc(output + VFSB_OFF_HEADER_SIZE, VIRTIO_FS_BACKEND_HEADER_SIZE);
	le16enc(output + VFSB_OFF_FLAGS, header->flags);
	le32enc(output + VFSB_OFF_PAYLOAD_LEN, header->payload_len);
	le64enc(output + VFSB_OFF_REQUEST_ID, header->request_id);
	le64enc(output + VFSB_OFF_INCARNATION, header->incarnation);
	le32enc(output + VFSB_OFF_STATUS, (uint32_t)header->status);
	return (0);
}

int
virtio_fs_backend_header_decode(const void *input, size_t input_len,
    struct virtio_fs_backend_header *header)
{
	const uint8_t *bytes;
	struct virtio_fs_backend_header decoded;
	int error;

	if (input == NULL || header == NULL)
		return (EINVAL);
	if (input_len != VIRTIO_FS_BACKEND_HEADER_SIZE)
		return (EMSGSIZE);
	bytes = input;
	if (le32dec(bytes + VFSB_OFF_MAGIC) != VIRTIO_FS_BACKEND_MAGIC ||
	    le16dec(bytes + VFSB_OFF_HEADER_SIZE) !=
	    VIRTIO_FS_BACKEND_HEADER_SIZE ||
	    le32dec(bytes + VFSB_OFF_RESERVED) != 0)
		return (EPROTO);
	decoded.version = le16dec(bytes + VFSB_OFF_VERSION);
	decoded.type = le16dec(bytes + VFSB_OFF_TYPE);
	decoded.flags = le16dec(bytes + VFSB_OFF_FLAGS);
	decoded.payload_len = le32dec(bytes + VFSB_OFF_PAYLOAD_LEN);
	decoded.request_id = le64dec(bytes + VFSB_OFF_REQUEST_ID);
	decoded.incarnation = le64dec(bytes + VFSB_OFF_INCARNATION);
	decoded.status = (int32_t)le32dec(bytes + VFSB_OFF_STATUS);
	error = virtio_fs_backend_header_validate(&decoded);
	if (error != 0)
		return (EPROTO);
	*header = decoded;
	return (0);
}

static int
virtio_fs_backend_hello_validate(const struct virtio_fs_backend_hello *hello)
{

	if (hello == NULL ||
	    hello->minimum_version != VIRTIO_FS_BACKEND_VERSION ||
	    hello->maximum_version != VIRTIO_FS_BACKEND_VERSION ||
	    (hello->features & ~VIRTIO_FS_BACKEND_F_ALL) != 0 ||
	    ((hello->features & VIRTIO_FS_BACKEND_F_STATE_TRANSFER) != 0 &&
	    (hello->features & VIRTIO_FS_BACKEND_F_FREEZE) == 0) ||
	    hello->maximum_message == 0 ||
	    hello->maximum_message > VIRTIO_FS_BACKEND_MAX_FRAME ||
	    hello->maximum_inflight == 0 ||
	    hello->maximum_inflight > VIRTIO_FS_BACKEND_MAX_INFLIGHT ||
	    hello->maximum_pending_bytes < hello->maximum_message ||
	    hello->maximum_pending_bytes >
	    VIRTIO_FS_BACKEND_MAX_PENDING_BYTES)
		return (EINVAL);
	return (0);
}

int
virtio_fs_backend_hello_encode(const struct virtio_fs_backend_hello *hello,
    uint8_t output[VIRTIO_FS_BACKEND_HELLO_SIZE])
{
	int error;

	if (output == NULL)
		return (EINVAL);
	error = virtio_fs_backend_hello_validate(hello);
	if (error != 0)
		return (error);
	le16enc(output, hello->minimum_version);
	le16enc(output + 2, hello->maximum_version);
	le32enc(output + 4, hello->features);
	le32enc(output + 8, hello->maximum_message);
	le32enc(output + 12, hello->maximum_inflight);
	le32enc(output + 16, hello->maximum_pending_bytes);
	return (0);
}

int
virtio_fs_backend_hello_decode(const void *input, size_t input_len,
    struct virtio_fs_backend_hello *hello)
{
	const uint8_t *bytes;
	struct virtio_fs_backend_hello decoded;
	int error;

	if (input == NULL || hello == NULL)
		return (EINVAL);
	if (input_len != VIRTIO_FS_BACKEND_HELLO_SIZE)
		return (EMSGSIZE);
	bytes = input;
	decoded.minimum_version = le16dec(bytes);
	decoded.maximum_version = le16dec(bytes + 2);
	decoded.features = le32dec(bytes + 4);
	decoded.maximum_message = le32dec(bytes + 8);
	decoded.maximum_inflight = le32dec(bytes + 12);
	decoded.maximum_pending_bytes = le32dec(bytes + 16);
	error = virtio_fs_backend_hello_validate(&decoded);
	if (error != 0)
		return (EPROTO);
	*hello = decoded;
	return (0);
}

void
virtio_fs_backend_session_init(struct virtio_fs_backend_session *session)
{

	if (session == NULL)
		return;
	memset(session, 0, sizeof(*session));
	session->phase = VIRTIO_FS_BACKEND_DISCONNECTED;
}

int
virtio_fs_backend_start_hello(struct virtio_fs_backend_session *session,
    uint64_t request_id, const struct virtio_fs_backend_hello *offer)
{
	int error;

	if (session == NULL || request_id == 0 ||
	    request_id > VIRTIO_FS_BACKEND_REQUEST_ID_MAX)
		return (EINVAL);
	error = virtio_fs_backend_hello_validate(offer);
	if (error != 0)
		return (error);
	if (session->phase != VIRTIO_FS_BACKEND_DISCONNECTED)
		return (EBUSY);
	/*
	 * Incarnations distinguish replies from earlier backend connections.
	 * Once the counter is exhausted, reconnecting would make stale replies
	 * indistinguishable from current ones.
	 */
	if (session->incarnation == UINT64_MAX)
		return (EOVERFLOW);
	session->phase = VIRTIO_FS_BACKEND_NEGOTIATING;
	session->version = VIRTIO_FS_BACKEND_VERSION;
	session->features = offer->features;
	session->maximum_message = offer->maximum_message;
	session->maximum_inflight = offer->maximum_inflight;
	session->maximum_pending_bytes = offer->maximum_pending_bytes;
	session->pending_control_id = request_id;
	return (0);
}

int
virtio_fs_backend_finish_hello(struct virtio_fs_backend_session *session,
    const struct virtio_fs_backend_header *header,
    const struct virtio_fs_backend_hello *selection)
{

	if (session == NULL || header == NULL)
		return (EINVAL);
	if (virtio_fs_backend_header_validate(header) != 0)
		return (EPROTO);
	if (session->phase != VIRTIO_FS_BACKEND_NEGOTIATING ||
	    header->type != VIRTIO_FS_BACKEND_HELLO_REPLY ||
	    header->request_id != session->pending_control_id ||
	    header->incarnation != 0)
		return (EPROTO);
	if (header->status != 0) {
		virtio_fs_backend_disconnect(session);
		return (ECONNREFUSED);
	}
	if (selection == NULL) {
		virtio_fs_backend_disconnect(session);
		return (EPROTO);
	}
	if (virtio_fs_backend_hello_validate(selection) != 0 ||
	    selection->minimum_version != selection->maximum_version ||
	    selection->minimum_version != VIRTIO_FS_BACKEND_VERSION ||
	    (selection->features & ~session->features) != 0 ||
	    selection->maximum_message > session->maximum_message ||
	    selection->maximum_inflight > session->maximum_inflight ||
	    selection->maximum_pending_bytes >
	    session->maximum_pending_bytes) {
		virtio_fs_backend_disconnect(session);
		return (EPROTO);
	}
	session->phase = VIRTIO_FS_BACKEND_ACTIVE;
	session->version = VIRTIO_FS_BACKEND_VERSION;
	session->features = selection->features;
	session->maximum_message = selection->maximum_message;
	session->maximum_inflight = selection->maximum_inflight;
	session->maximum_pending_bytes = selection->maximum_pending_bytes;
	if (session->incarnation == 0)
		session->incarnation = 1;
	session->pending_control_id = 0;
	session->control_failure_phase = VIRTIO_FS_BACKEND_DISCONNECTED;
	return (0);
}

int
virtio_fs_backend_start_control(struct virtio_fs_backend_session *session,
    enum virtio_fs_backend_message_type type, uint64_t request_id)
{
	enum virtio_fs_backend_phase next;
	uint32_t required_feature;

	if (session == NULL ||
	    (request_id & VIRTIO_FS_BACKEND_CONTROL_ID_BIT) == 0)
		return (EINVAL);
	required_feature = 0;
	switch (type) {
	case VIRTIO_FS_BACKEND_QUIESCE:
		if (session->phase != VIRTIO_FS_BACKEND_ACTIVE)
			return (EBUSY);
		next = VIRTIO_FS_BACKEND_QUIESCING;
		required_feature = VIRTIO_FS_BACKEND_F_FREEZE;
		break;
	case VIRTIO_FS_BACKEND_THAW:
		if (session->phase != VIRTIO_FS_BACKEND_QUIESCED)
			return (EBUSY);
		next = VIRTIO_FS_BACKEND_THAWING;
		required_feature = VIRTIO_FS_BACKEND_F_FREEZE;
		break;
	case VIRTIO_FS_BACKEND_SHUTDOWN:
		if (session->phase != VIRTIO_FS_BACKEND_ACTIVE &&
		    session->phase != VIRTIO_FS_BACKEND_QUIESCED)
			return (EBUSY);
		session->control_failure_phase = session->phase;
		next = VIRTIO_FS_BACKEND_SHUTTING_DOWN;
		break;
	default:
		return (EINVAL);
	}
	if ((session->features & required_feature) != required_feature)
		return (ENOTSUP);
	if (type != VIRTIO_FS_BACKEND_SHUTDOWN)
		session->control_failure_phase = session->phase;
	session->phase = next;
	session->pending_control_id = request_id;
	return (0);
}

int
virtio_fs_backend_finish_control(struct virtio_fs_backend_session *session,
    const struct virtio_fs_backend_header *header)
{
	enum virtio_fs_backend_message_type expected;
	enum virtio_fs_backend_phase success, failure;

	if (session == NULL || header == NULL)
		return (EINVAL);
	if (virtio_fs_backend_header_validate(header) != 0)
		return (EPROTO);
	switch (session->phase) {
	case VIRTIO_FS_BACKEND_QUIESCING:
		expected = VIRTIO_FS_BACKEND_QUIESCE_REPLY;
		success = VIRTIO_FS_BACKEND_QUIESCED;
		failure = VIRTIO_FS_BACKEND_ACTIVE;
		break;
	case VIRTIO_FS_BACKEND_THAWING:
		expected = VIRTIO_FS_BACKEND_THAW_REPLY;
		success = VIRTIO_FS_BACKEND_ACTIVE;
		failure = VIRTIO_FS_BACKEND_QUIESCED;
		break;
	case VIRTIO_FS_BACKEND_SHUTTING_DOWN:
		expected = VIRTIO_FS_BACKEND_SHUTDOWN_REPLY;
		success = VIRTIO_FS_BACKEND_CLOSED;
		failure = session->control_failure_phase;
		break;
	default:
		return (EBUSY);
	}
	if (header->type != expected ||
	    header->request_id != session->pending_control_id ||
	    header->incarnation != session->incarnation)
		return (EPROTO);
	session->phase = header->status == 0 ? success : failure;
	session->pending_control_id = 0;
	session->control_failure_phase = VIRTIO_FS_BACKEND_DISCONNECTED;
	return (header->status == 0 ? 0 : EIO);
}

void
virtio_fs_backend_disconnect(struct virtio_fs_backend_session *session)
{
	uint64_t incarnation;

	if (session == NULL)
		return;
	incarnation = session->incarnation;
	memset(session, 0, sizeof(*session));
	session->phase = VIRTIO_FS_BACKEND_DISCONNECTED;
	session->incarnation = incarnation == UINT64_MAX ?
	    UINT64_MAX : incarnation + 1;
}
