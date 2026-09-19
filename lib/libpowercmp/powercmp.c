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
};

int
powercmp_validate_message(const struct powercmp_msg *msg, size_t length,
    enum powercmp_message_role role)
{

	if (msg == NULL || length < sizeof(*msg))
		return (-1);
	if (msg->magic != POWERCMP_MAGIC || msg->version != POWERCMP_ABI_VERSION)
		return (-1);
	if (length != sizeof(*msg) &&
	    length != sizeof(*msg) + sizeof(struct powercmp_body))
		return (-1);
	switch (msg->opcode) {
	case POWERCMP_OP_HELLO:
	case POWERCMP_OP_STATES:
	case POWERCMP_OP_SUSPEND:
		break;
	default:
		return (-1);
	}
	if (role == POWERCMP_MESSAGE_REPLY && msg->status > 0)
		return (-1);
	return (0);
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
		return (-1);
	qmsg = request;
	rmsg = (const void *)reply->bytes;
	if (incoming.nfds != 0 ||
	    powercmp_validate_message(rmsg, incoming.length,
	    POWERCMP_MESSAGE_REPLY) == -1 || rmsg->opcode != qmsg->opcode) {
		(void)service_session_fail(client->session, EPROTO);
		return (errno = EPROTO, -1);
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
	msg->version = POWERCMP_ABI_VERSION;
	msg->opcode = opcode;
}

int
powercmp_client_open(struct powercmp_client **clientp)
{
	union powercmp_buffer request, reply;
	struct powercmp_client *client;
	size_t reply_len;
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
	build_header(&request, POWERCMP_OP_HELLO);
	if (call(client, &request, sizeof(struct powercmp_msg), &reply,
	    &reply_len) == -1) {
		error = errno;
		powercmp_client_close(client);
		return (errno = error, -1);
	}
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
