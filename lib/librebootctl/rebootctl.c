/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <sys/param.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libservice.h>

#include "rebootctl.h"
#include "rebootctl_server.h"

struct rebootctl_client {
	struct service_session *session;
	pid_t owner;
};

static int
header_valid(const struct rebootctl_msg *msg, size_t length, bool reply)
{

	if (msg == NULL || length < sizeof(*msg) ||
	    length > REBOOTCTL_MAX_MESSAGE || msg->magic != REBOOTCTL_MAGIC ||
	    msg->version != REBOOTCTL_ABI_VERSION ||
	    msg->opcode < REBOOTCTL_OP_REBOOT ||
	    msg->opcode > REBOOTCTL_OP_CANCEL || msg->flags != 0 ||
	    (!reply && msg->status != 0) ||
	    (reply && (msg->status > 0 || msg->status < -ELAST))) {
		errno = EPROTO;
		return (-1);
	}
	return (0);
}

int
rebootctl_validate_request(const struct rebootctl_msg *msg, size_t length)
{
	const struct rebootctl_request *request;

	if (header_valid(msg, length, false) == -1)
		return (-1);
	if (msg->opcode == REBOOTCTL_OP_STATUS ||
	    msg->opcode == REBOOTCTL_OP_CANCEL)
		return (length == sizeof(*msg) ? 0 : (errno = EPROTO, -1));
	if (length != sizeof(*msg) + sizeof(*request))
		return (errno = EPROTO, -1);
	request = (const void *)(msg + 1);
	if (request->delay_ms > REBOOTCTL_MAX_DELAY_MS ||
	    (msg->opcode == REBOOTCTL_OP_SHUTDOWN && request->howto != 0))
		return (errno = EPROTO, -1);
	return (0);
}

int
rebootctl_validate_reply(const struct rebootctl_msg *msg, size_t length)
{
	const struct rebootctl_status_reply *status;

	if (header_valid(msg, length, true) == -1)
		return (-1);
	if (msg->status != 0)
		return (length == sizeof(*msg) ? 0 : (errno = EPROTO, -1));
	if (msg->opcode != REBOOTCTL_OP_STATUS)
		return (length == sizeof(*msg) ? 0 : (errno = EPROTO, -1));
	if (length != sizeof(*msg) + sizeof(*status))
		return (errno = EPROTO, -1);
	status = (const void *)(msg + 1);
	if (status->pending > 1 ||
	    (status->pending == 0 && (status->howto != 0 ||
	    status->request_id != 0 || status->requested_at_ns != 0 ||
	    status->execute_at_ns != 0)) ||
	    (status->pending != 0 && (status->request_id == 0 ||
	    status->requested_at_ns == 0 ||
	    status->execute_at_ns < status->requested_at_ns ||
	    (status->howto & ~REBOOTCTL_ALLOWED_FLAGS) != 0)))
		return (errno = EPROTO, -1);
	return (0);
}

static const char *
notification_topic(uint32_t state)
{

	switch (state) {
	case REBOOTCTL_NOTIFICATION_REQUESTED:
		return (REBOOTCTL_NOTIFY_REQUESTED);
	case REBOOTCTL_NOTIFICATION_SCHEDULED:
		return (REBOOTCTL_NOTIFY_SCHEDULED);
	case REBOOTCTL_NOTIFICATION_IMMINENT:
		return (REBOOTCTL_NOTIFY_IMMINENT);
	case REBOOTCTL_NOTIFICATION_CANCELLED:
		return (REBOOTCTL_NOTIFY_CANCELLED);
	default:
		return (NULL);
	}
}

static bool
zero_region(const void *data, size_t length)
{
	const unsigned char *bytes;
	size_t i;

	bytes = data;
	for (i = 0; i < length; i++)
		if (bytes[i] != 0)
			return (false);
	return (true);
}

int
rebootctl_notification_decode(const char *topic, const void *payload,
    size_t length, struct rebootctl_notification *notification)
{
	struct rebootctl_notification decoded;
	const struct rebootctl_notification *wire;
	const char *expected;
	size_t requester_length;

	if (topic == NULL || payload == NULL || notification == NULL)
		return (errno = EINVAL, -1);
	if (length != sizeof(*wire))
		return (errno = EPROTO, -1);
	memcpy(&decoded, payload, sizeof(decoded));
	wire = &decoded;
	expected = notification_topic(wire->state);
	requester_length = wire->requester_length;
	if (wire->version != REBOOTCTL_ABI_VERSION || expected == NULL ||
	    strcmp(topic, expected) != 0 || wire->request_id == 0 ||
	    wire->requested_at_ns == 0 ||
	    wire->execute_at_ns < wire->requested_at_ns ||
	    wire->remaining_ms > REBOOTCTL_MAX_DELAY_MS ||
	    (wire->howto & ~REBOOTCTL_ALLOWED_FLAGS) != 0 ||
	    wire->error < 0 || wire->error > ELAST ||
	    (wire->state != REBOOTCTL_NOTIFICATION_CANCELLED &&
	    wire->error != 0) ||
	    (wire->state == REBOOTCTL_NOTIFICATION_CANCELLED &&
	    wire->error == 0) || requester_length == 0 ||
	    requester_length >= sizeof(wire->requester) ||
	    wire->reserved16 != 0 ||
	    wire->requester[requester_length] != '\0' ||
	    strnlen(wire->requester, sizeof(wire->requester)) !=
	    requester_length || !zero_region(wire->requester + requester_length,
	    sizeof(wire->requester) - requester_length))
		return (errno = EPROTO, -1);
	*notification = decoded;
	return (0);
}

static int
call(struct rebootctl_client *client, uint16_t opcode, uint32_t howto,
    uint32_t delay_ms, struct rebootctl_status_reply *status)
{
	struct {
		struct rebootctl_msg msg;
		struct rebootctl_request request;
	} outgoing_wire;
	struct {
		struct rebootctl_msg msg;
		struct rebootctl_status_reply status;
	} incoming_wire;
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;
	size_t request_length;

	if (client == NULL || client->owner != getpid())
		return (errno = client == NULL ? EINVAL : ECHILD, -1);
	memset(&outgoing_wire, 0, sizeof(outgoing_wire));
	outgoing_wire.msg.magic = REBOOTCTL_MAGIC;
	outgoing_wire.msg.version = REBOOTCTL_ABI_VERSION;
	outgoing_wire.msg.opcode = opcode;
	outgoing_wire.request.howto = howto;
	outgoing_wire.request.delay_ms = delay_ms;
	request_length = sizeof(outgoing_wire.msg) +
	    (opcode == REBOOTCTL_OP_STATUS || opcode == REBOOTCTL_OP_CANCEL ?
	    0 : sizeof(outgoing_wire.request));
	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = &outgoing_wire;
	outgoing.length = request_length;
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = &incoming_wire;
	incoming.capacity = sizeof(incoming_wire);
	options.timeout_ms = 30000;
	if (service_session_call(client->session, &outgoing, &incoming,
	    &options) == -1)
		return (-1);
	if (incoming.nfds != 0 ||
	    rebootctl_validate_reply(&incoming_wire.msg, incoming.length) == -1 ||
	    incoming_wire.msg.opcode != opcode) {
		(void)service_session_fail(client->session, EPROTO);
		return (errno = EPROTO, -1);
	}
	if (incoming_wire.msg.status != 0)
		return (errno = -incoming_wire.msg.status, -1);
	if (status != NULL)
		*status = incoming_wire.status;
	return (0);
}

int
rebootctl_client_open(struct rebootctl_client **clientp)
{
	struct service_context *context;
	struct rebootctl_client *client;
	int fd, error;

	if (clientp == NULL)
		return (errno = EINVAL, -1);
	*clientp = NULL;
	if (service_acquire(&context) == -1)
		return (-1);
	error = service_connect(context, REBOOTCTL_INTERFACE, &fd) == -1 ?
	    errno : 0;
	service_release(context);
	if (error != 0)
		return (errno = error, -1);
	client = calloc(1, sizeof(*client));
	if (client == NULL) {
		error = errno;
		close(fd);
		return (errno = error, -1);
	}
	if (service_session_create(fd, &client->session) == -1) {
		error = errno;
		close(fd);
		free(client);
		return (errno = error, -1);
	}
	client->owner = getpid();
	*clientp = client;
	return (0);
}

void
rebootctl_client_close(struct rebootctl_client *client)
{

	if (client == NULL)
		return;
	if (client->owner == getpid())
		service_session_close(client->session);
	free(client);
}

int
rebootctl_reboot(struct rebootctl_client *client, uint32_t howto)
{

	if ((howto & ~REBOOTCTL_ALLOWED_FLAGS) != 0)
		return (errno = EINVAL, -1);
	return (rebootctl_reboot_after(client, howto,
	    REBOOTCTL_DEFAULT_DELAY_MS));
}

int
rebootctl_shutdown(struct rebootctl_client *client)
{

	return (rebootctl_shutdown_after(client, REBOOTCTL_DEFAULT_DELAY_MS));
}

int
rebootctl_reboot_after(struct rebootctl_client *client, uint32_t howto,
    uint32_t delay_ms)
{

	if ((howto & ~REBOOTCTL_ALLOWED_FLAGS) != 0 ||
	    delay_ms > REBOOTCTL_MAX_DELAY_MS)
		return (errno = EINVAL, -1);
	return (call(client, REBOOTCTL_OP_REBOOT, howto, delay_ms, NULL));
}

int
rebootctl_shutdown_after(struct rebootctl_client *client, uint32_t delay_ms)
{

	if (delay_ms > REBOOTCTL_MAX_DELAY_MS)
		return (errno = EINVAL, -1);
	return (call(client, REBOOTCTL_OP_SHUTDOWN, 0, delay_ms, NULL));
}

int
rebootctl_cancel(struct rebootctl_client *client)
{

	return (call(client, REBOOTCTL_OP_CANCEL, 0, 0, NULL));
}

int
rebootctl_status(struct rebootctl_client *client, bool *pending)
{
	struct rebootctl_status_reply status;

	if (pending == NULL)
		return (errno = EINVAL, -1);
	if (rebootctl_status_detailed(client, &status) == -1)
		return (-1);
	*pending = status.pending != 0;
	return (0);
}

int
rebootctl_status_detailed(struct rebootctl_client *client,
    struct rebootctl_status_reply *status)
{

	if (status == NULL)
		return (errno = EINVAL, -1);
	return (call(client, REBOOTCTL_OP_STATUS, 0, 0, status));
}
