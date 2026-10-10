/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * libpowercmp implementation.  See powercmp.h and powercmp_protocol.h.
 */
#include <sys/capsicum.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libservice.h>

#include "powercmp.h"

union powercmp_buffer {
	max_align_t	align;
	uint8_t		bytes[POWERCMP_MAX_MESSAGE];
};

struct powercmp_client {
	struct service_session	*session;
	pid_t			 owner;
	int terminal_error;
};

int
powercmp_validate_message(const struct powercmp_msg *msg, size_t length,
    enum powercmp_message_role role)
{
	const struct powercmp_body *body;
	size_t expected;
	if (msg == NULL || length < sizeof(*msg) ||
	    msg->magic != POWERCMP_MAGIC ||
	    (role != POWERCMP_MESSAGE_REQUEST &&
		role != POWERCMP_MESSAGE_REPLY) ||
	    msg->flags != 0 || msg->opcode < POWERCMP_OP_STATES ||
	    msg->opcode > POWERCMP_OP_INHIBITORS ||
	    (role == POWERCMP_MESSAGE_REQUEST && msg->status != 0) ||
	    msg->status > 0 || msg->status < -ELAST)
		return (errno = EPROTO, -1);
	expected = sizeof(*msg);
	if ((role == POWERCMP_MESSAGE_REQUEST &&
		msg->opcode == POWERCMP_OP_SUSPEND) ||
	    (role == POWERCMP_MESSAGE_REPLY && msg->status == 0 &&
		(msg->opcode == POWERCMP_OP_STATES ||
		    msg->opcode == POWERCMP_OP_INHIBITORS)))
		expected += sizeof(*body);
	if (length != expected)
		return (errno = EPROTO, -1);
	if (expected > sizeof(*msg)) {
		body = (const void *)(msg + 1);
		if (body->reserved[0] != 0 || body->reserved[1] != 0 ||
		    (role == POWERCMP_MESSAGE_REQUEST &&
			body->supported != 0) ||
		    (role == POWERCMP_MESSAGE_REPLY && body->state != 0))
			return (errno = EPROTO, -1);
	}
	return (0);
}

/* A lost/ambiguous RPC drops the connection and hence every session lease.
 * Keep the error on the handle: callers cannot accidentally reuse or reopen it.
 */
static int
client_disconnect(struct powercmp_client *client, int error)
{
	if (client->session != NULL) {
		service_session_close(client->session);
		client->session = NULL;
	}
	client->terminal_error = error != 0 ? error : EIO;
	return (errno = client->terminal_error, -1);
}

static int
call(struct powercmp_client *client, const void *request, size_t req_len,
    union powercmp_buffer *reply, size_t *reply_len)
{
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;
	const struct powercmp_msg *qmsg, *rmsg;

	if (client == NULL)
		return (errno = EINVAL, -1);
	if (client->owner != getpid())
		return (errno = ECHILD, -1);
	if (client->terminal_error != 0)
		return (errno = client->terminal_error, -1);
	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = __DECONST(void *, request);
	outgoing.length = req_len;
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = reply;
	incoming.capacity = sizeof(*reply);
	options.timeout_ms = 5000;
	if (service_session_call(client->session, &outgoing, &incoming,
	    &options) == -1)
		return (client_disconnect(client, errno));
	qmsg = request;
	rmsg = (const void *)reply->bytes;
	if (incoming.nfds != 0 ||
	    powercmp_validate_message(rmsg, incoming.length,
	    POWERCMP_MESSAGE_REPLY) == -1 || rmsg->opcode != qmsg->opcode) {
		return (client_disconnect(client, EPROTO));
	}
	if (rmsg->status != 0)
		return (errno = -rmsg->status, -1);
	if (reply_len != NULL)
		*reply_len = incoming.length;
	return (0);
}

static void
build_header(union powercmp_buffer *buf, uint16_t opcode)
{
	struct powercmp_msg *msg = (void *)buf->bytes;

	memset(buf, 0, sizeof(*buf));
	msg->magic = POWERCMP_MAGIC;
	msg->opcode = opcode;
}

int
powercmp_client_open(struct powercmp_client **clientp)
{
	struct powercmp_client *client;
	int error, fd, owned;

	if (clientp == NULL)
		return (errno = EINVAL, -1);
	*clientp = NULL;
	fd = -1;
	if (service_open(POWERCMP_INTERFACE, &fd) == -1)
		return (-1);
	if (cap_xfer_limit(fd, CAP_XFER_NONE) == -1 ||
	    cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED) == -1) {
		error = errno;
		(void)close(fd);
		return (errno = error, -1);
	}
	owned = fcntl(fd, F_DUPFD_CLOEXEC, 0);
	error = owned == -1 ? errno : 0;
	(void)close(fd);
	if (error != 0)
		return (errno = error, -1);
	client = calloc(1, sizeof(*client));
	if (client == NULL) {
		(void)close(owned);
		return (-1);
	}
	client->owner = getpid();
	if (service_session_create(owned, &client->session) == -1) {
		error = errno;
		(void)close(owned);
		free(client);
		return (errno = error, -1);
	}
	/* The session owns its duplicate, not this constructor descriptor. */
	(void)close(owned);
	*clientp = client;
	return (0);
}

void
powercmp_client_close(struct powercmp_client *client)
{

	if (client == NULL)
		return;
	if (client->owner == getpid() && client->session != NULL)
		service_session_close(client->session);
	free(client);
}

int
powercmp_states(struct powercmp_client *client, uint32_t *supported)
{
	union powercmp_buffer request, reply;
	const struct powercmp_body *body;
	size_t reply_len;

	if (supported == NULL)
		return (errno = EINVAL, -1);
	build_header(&request, POWERCMP_OP_STATES);
	if (call(client, &request, sizeof(struct powercmp_msg), &reply,
	    &reply_len) == -1)
		return (-1);
	if (reply_len != sizeof(struct powercmp_msg) + sizeof(*body))
		return (errno = EPROTO, -1);
	body = (const void *)(reply.bytes + sizeof(struct powercmp_msg));
	*supported = body->supported;
	return (0);
}

int
powercmp_suspend(struct powercmp_client *client, uint32_t state)
{
	union powercmp_buffer request, reply;
	struct powercmp_body *body;

	if (state < 1 || state > 5)
		return (errno = EINVAL, -1);
	build_header(&request, POWERCMP_OP_SUSPEND);
	body = (void *)(request.bytes + sizeof(struct powercmp_msg));
	body->state = state;
	return (call(client, &request,
	    sizeof(struct powercmp_msg) + sizeof(*body), &reply, NULL));
}

static int
inhibitor_call(struct powercmp_client *client, uint32_t opcode, uint32_t *count)
{
	union powercmp_buffer request, reply;
	const struct powercmp_body *body;
	size_t length;
	build_header(&request, opcode);
	if (call(client, &request, sizeof(struct powercmp_msg), &reply,
		&length) == -1)
		return (-1);
	if (length !=
	    sizeof(struct powercmp_msg) + (count != NULL ? sizeof(*body) : 0)) {
		return (client_disconnect(client, EPROTO));
	}
	if (count != NULL) {
		body = (const void *)(reply.bytes +
		    sizeof(struct powercmp_msg));
		*count = body->supported;
	}
	return (0);
}
int
powercmp_inhibit(struct powercmp_client *c)
{
	return (inhibitor_call(c, POWERCMP_OP_INHIBIT, NULL));
}
int
powercmp_uninhibit(struct powercmp_client *c)
{
	return (inhibitor_call(c, POWERCMP_OP_UNINHIBIT, NULL));
}
int
powercmp_inhibitors(struct powercmp_client *c, uint32_t *count)
{
	if (count == NULL)
		return (errno = EINVAL, -1);
	return (inhibitor_call(c, POWERCMP_OP_INHIBITORS, count));
}
