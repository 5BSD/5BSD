/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * libtimecmp implementation.  See timecmp.h and timecmp_protocol.h.
 */
#include <sys/capsicum.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libservice.h>

#include "timecmp.h"

union timecmp_buffer {
	max_align_t	align;
	uint8_t		bytes[TIMECMP_MAX_MESSAGE];
};

struct timecmp_client {
	struct service_session	*session;
	pid_t			 owner;
};

int
timecmp_validate_message(const struct timecmp_msg *msg, size_t length,
    enum timecmp_message_role role)
{

	if (msg == NULL || length < sizeof(*msg))
		return (-1);
	if (msg->magic != TIMECMP_MAGIC || msg->version != TIMECMP_ABI_VERSION)
		return (-1);
	if (length != sizeof(*msg) &&
	    length != sizeof(*msg) + sizeof(struct timecmp_time))
		return (-1);
	switch (msg->opcode) {
	case TIMECMP_OP_HELLO:
	case TIMECMP_OP_GET:
	case TIMECMP_OP_SET:
	case TIMECMP_OP_ADJUST:
		break;
	default:
		return (-1);
	}
	if (role == TIMECMP_MESSAGE_REPLY && msg->status > 0)
		return (-1);
	return (0);
}

/*
 * One request/reply exchange.  request/req_len is the caller's built message;
 * on success reply holds the reply and *reply_len its length.
 */
static int
call(struct timecmp_client *client, const void *request, size_t req_len,
    union timecmp_buffer *reply, size_t *reply_len)
{
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;
	const struct timecmp_msg *qmsg, *rmsg;

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
	    timecmp_validate_message(rmsg, incoming.length,
	    TIMECMP_MESSAGE_REPLY) == -1 || rmsg->opcode != qmsg->opcode) {
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
build_header(union timecmp_buffer *buf, uint16_t opcode)
{
	struct timecmp_msg *msg = (void *)buf->bytes;

	memset(buf, 0, sizeof(*buf));
	msg->magic = TIMECMP_MAGIC;
	msg->version = TIMECMP_ABI_VERSION;
	msg->opcode = opcode;
}

int
timecmp_client_open(struct timecmp_client **clientp)
{
	union timecmp_buffer request, reply;
	struct timecmp_client *client;
	size_t reply_len;
	int error, fd, owned;

	if (clientp == NULL)
		return (errno = EINVAL, -1);
	*clientp = NULL;
	fd = -1;
	if (service_open(TIMECMP_INTERFACE, &fd) == -1)
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
	build_header(&request, TIMECMP_OP_HELLO);
	if (call(client, &request, sizeof(struct timecmp_msg), &reply,
	    &reply_len) == -1) {
		error = errno;
		timecmp_client_close(client);
		return (errno = error, -1);
	}
	*clientp = client;
	return (0);
}

void
timecmp_client_close(struct timecmp_client *client)
{

	if (client == NULL)
		return;
	if (client->owner == getpid() && client->session != NULL)
		service_session_close(client->session);
	free(client);
}

int
timecmp_get(struct timecmp_client *client, struct timespec *ts)
{
	union timecmp_buffer request, reply;
	const struct timecmp_time *body;
	size_t reply_len;

	if (ts == NULL)
		return (errno = EINVAL, -1);
	build_header(&request, TIMECMP_OP_GET);
	if (call(client, &request, sizeof(struct timecmp_msg), &reply,
	    &reply_len) == -1)
		return (-1);
	if (reply_len != sizeof(struct timecmp_msg) + sizeof(*body))
		return (errno = EPROTO, -1);
	body = (const void *)(reply.bytes + sizeof(struct timecmp_msg));
	ts->tv_sec = (time_t)body->sec;
	ts->tv_nsec = body->nsec;
	return (0);
}

int
timecmp_set(struct timecmp_client *client, const struct timespec *ts)
{
	union timecmp_buffer request, reply;
	struct timecmp_time *body;

	if (ts == NULL || ts->tv_nsec < 0 || ts->tv_nsec > 999999999)
		return (errno = EINVAL, -1);
	build_header(&request, TIMECMP_OP_SET);
	body = (void *)(request.bytes + sizeof(struct timecmp_msg));
	body->sec = ts->tv_sec;
	body->nsec = (int32_t)ts->tv_nsec;
	body->present = 1;
	return (call(client, &request,
	    sizeof(struct timecmp_msg) + sizeof(*body), &reply, NULL));
}

int
timecmp_adjust(struct timecmp_client *client, const struct timeval *delta,
    struct timeval *old)
{
	union timecmp_buffer request, reply;
	const struct timecmp_time *rbody;
	struct timecmp_time *body;
	size_t reply_len;

	if (delta == NULL || delta->tv_usec < -999999 || delta->tv_usec > 999999)
		return (errno = EINVAL, -1);
	build_header(&request, TIMECMP_OP_ADJUST);
	body = (void *)(request.bytes + sizeof(struct timecmp_msg));
	body->sec = delta->tv_sec;
	body->nsec = (int32_t)delta->tv_usec * 1000;
	body->present = 1;
	if (call(client, &request,
	    sizeof(struct timecmp_msg) + sizeof(*body), &reply,
	    &reply_len) == -1)
		return (-1);
	if (old != NULL) {
		if (reply_len != sizeof(struct timecmp_msg) + sizeof(*rbody))
			return (errno = EPROTO, -1);
		rbody = (const void *)(reply.bytes + sizeof(struct timecmp_msg));
		old->tv_sec = (time_t)rbody->sec;
		old->tv_usec = rbody->present ? rbody->nsec / 1000 : 0;
	}
	return (0);
}
