/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libservice.h>

#include "tracecmp.h"
#include "tracecmp_probes.h"

union tracecmp_buffer {
	max_align_t align;
	uint8_t bytes[TRACECMP_MAX_MESSAGE];
};

static int
tracecmp_header_validate(const struct tracecmp_msg *msg, size_t length,
    enum tracecmp_message_role role)
{

	if (msg == NULL || length < sizeof(*msg) ||
	    length > TRACECMP_MAX_MESSAGE ||
	    (role != TRACECMP_MESSAGE_REQUEST &&
	    role != TRACECMP_MESSAGE_REPLY &&
	    role != TRACECMP_MESSAGE_EVENT) ||
	    msg->magic != TRACECMP_MAGIC ||
	    msg->version != TRACECMP_ABI_VERSION ||
	    msg->opcode < TRACECMP_OP_HELLO ||
	    msg->opcode > TRACECMP_OP_STATS ||
	    (msg->flags & ~TRACECMP_MSG_F_MASK) != 0 ||
	    (role != TRACECMP_MESSAGE_REPLY && msg->status != 0) ||
	    (role == TRACECMP_MESSAGE_REPLY &&
	    (msg->status > 0 || msg->status < -ELAST))) {
		errno = EPROTO;
		return (-1);
	}
	return (0);
}

int
tracecmp_message_init(struct tracecmp_msg *msg, uint16_t opcode,
    uint32_t flags)
{

	if (msg == NULL || opcode < TRACECMP_OP_HELLO ||
	    opcode > TRACECMP_OP_STATS ||
	    (flags & ~TRACECMP_MSG_F_MASK) != 0) {
		errno = EINVAL;
		return (-1);
	}
	memset(msg, 0, sizeof(*msg));
	msg->magic = TRACECMP_MAGIC;
	msg->version = TRACECMP_ABI_VERSION;
	msg->opcode = opcode;
	msg->flags = flags;
	return (0);
}

int
tracecmp_message_init_reply(struct tracecmp_msg *reply,
    const struct tracecmp_msg *request, int status)
{

	if (reply == NULL || request == NULL ||
	    tracecmp_header_validate(request, sizeof(*request),
	    TRACECMP_MESSAGE_REQUEST) == -1 ||
	    status > 0 || status < -ELAST) {
		errno = EINVAL;
		return (-1);
	}
	memset(reply, 0, sizeof(*reply));
	reply->magic = TRACECMP_MAGIC;
	reply->version = TRACECMP_ABI_VERSION;
	reply->opcode = request->opcode;
	reply->status = status;
	return (0);
}

int
tracecmp_validate_message(const struct tracecmp_msg *msg, size_t length,
    enum tracecmp_message_role role)
{
	size_t payload;

	if (tracecmp_header_validate(msg, length, role) == -1)
		return (-1);
	payload = length - sizeof(*msg);
	if (role == TRACECMP_MESSAGE_EVENT) {
		errno = EPROTO;
		return (-1);
	}
	if (role == TRACECMP_MESSAGE_REQUEST) {
		if (payload != 0) {
			errno = EPROTO;
			return (-1);
		}
		return (0);
	}
	if (msg->status != 0 && payload != 0) {
		errno = EPROTO;
		return (-1);
	}
	if (msg->status != 0)
		return (0);
	if (msg->opcode == TRACECMP_OP_HELLO) {
		const struct tracecmp_hello_reply *hello;

		if (payload != sizeof(*hello))
			goto invalid;
		hello = (const void *)(msg + 1);
		if (hello->version != TRACECMP_ABI_VERSION ||
		    (hello->features & ~TRACECMP_FEATURE_RAW_DTRACE_FD) != 0 ||
		    hello->reserved[0] != 0 || hello->reserved[1] != 0)
			goto invalid;
	} else if (msg->opcode == TRACECMP_OP_STATS) {
		if (payload != sizeof(struct tracecmp_stats))
			goto invalid;
	} else if (payload != 0) {
		goto invalid;
	}
	return (0);

invalid:
	errno = EPROTO;
	return (-1);
}

int
tracecmp_validate_fds(const struct tracecmp_msg *msg, size_t nfds,
    enum tracecmp_message_role role)
{
	size_t expected;

	if (msg == NULL) {
		errno = EINVAL;
		return (-1);
	}
	expected = role == TRACECMP_MESSAGE_REPLY &&
	    msg->opcode == TRACECMP_OP_OPEN && msg->status == 0 ? 1 : 0;
	if (nfds != expected) {
		errno = EPROTO;
		return (-1);
	}
	return (0);
}

static int
rpc(struct service_session *client, uint16_t opcode,
    union tracecmp_buffer *reply,
    int *returned_fd)
{
	struct tracecmp_msg request, *message;
	struct service_call_options options =
	    SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;
	size_t received;

	memset(&request, 0, sizeof(request));
	if (tracecmp_message_init(&request, opcode, 0) == -1)
		return (-1);
	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = &request;
	outgoing.length = sizeof(request);
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = reply;
	incoming.capacity = sizeof(*reply);
	incoming.fds = returned_fd;
	incoming.fd_capacity = returned_fd != NULL ? 1 : 0;
	options.timeout_ms = 30000;
	if (service_session_call(client, &outgoing, &incoming, &options) == -1)
		return (-1);
	received = incoming.length;
	message = (void *)reply;
	if (tracecmp_validate_message(message, received,
	    TRACECMP_MESSAGE_REPLY) == -1 ||
	    tracecmp_validate_fds(message, incoming.nfds,
	    TRACECMP_MESSAGE_REPLY) == -1 ||
	    message->opcode != opcode) {
		if (incoming.nfds != 0 && returned_fd != NULL)
			close(*returned_fd);
		errno = EPROTO;
		return (-1);
	}
	if (message->status != 0) {
		errno = -message->status;
		return (-1);
	}
	return (0);
}

int
tracecmp_open(int *dtracefd)
{
	union tracecmp_buffer reply;
	struct tracecmp_hello_reply *hello;
	struct service_context *service;
	struct service_session *client;
	int fd, error, result;

	if (dtracefd == NULL) {
		errno = EINVAL;
		return (-1);
	}
	*dtracefd = -1;
	if (service_acquire(&service) == -1)
		return (-1);
	error = service_connect(service, TRACECMP_INTERFACE, &fd) == -1 ?
	    errno : 0;
	service_release(service);
	if (fd == -1) {
		errno = error;
		return (-1);
	}
	if (service_session_create(fd, &client) == -1) {
		error = errno;
		close(fd);
		errno = error;
		return (-1);
	}
	result = rpc(client, TRACECMP_OP_HELLO, &reply, NULL);
	if (result == 0) {
		hello = (void *)((struct tracecmp_msg *)reply.bytes + 1);
		if ((hello->features & TRACECMP_FEATURE_RAW_DTRACE_FD) == 0) {
			errno = EOPNOTSUPP;
			result = -1;
		}
	}
	if (result == 0)
		result = rpc(client, TRACECMP_OP_OPEN, &reply, dtracefd);
	error = result == -1 ? errno : 0;
	service_session_close(client);
	TRACECMP_PROBE_OPEN(__DECONST(char *, TRACECMP_INTERFACE), error);
	errno = error;
	return (result);
}
