/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/capsicum.h>
#include <sys/param.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libservice.h>

#include "auditcmp.h"
#include "auditcmp_server.h"

union auditcmp_buffer {
	max_align_t align;
	uint8_t bytes[AUDITCMP_MAX_MESSAGE];
};

struct auditcmp_client {
	struct service_session	*session;
	pid_t			 owner;
};

static bool
fixed_string_valid(const char *text, size_t length, size_t capacity)
{
	size_t i;
	unsigned char c;

	if (length == 0 || length > capacity ||
	    memchr(text, '\0', length) != NULL)
		return (false);
	for (i = 0; i < length; i++) {
		c = (unsigned char)text[i];
		if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		    (c >= '0' && c <= '9') || c == '.' || c == '_' ||
		    c == '-')
			continue;
		return (false);
	}
	return (memcmp(text + length, (char[AUDITCMP_MAX_SUBJECT]){},
	    capacity - length) == 0);
}

static int
header_validate(const struct auditcmp_msg *msg, size_t length,
    enum auditcmp_message_role role)
{

	if (msg == NULL || length < sizeof(*msg) ||
	    length > AUDITCMP_MAX_MESSAGE ||
	    (role != AUDITCMP_MESSAGE_REQUEST &&
	    role != AUDITCMP_MESSAGE_REPLY &&
	    role != AUDITCMP_MESSAGE_EVENT) ||
	    msg->magic != AUDITCMP_MAGIC ||
	    msg->version != AUDITCMP_ABI_VERSION ||
	    msg->opcode < AUDITCMP_OP_HELLO ||
	    msg->opcode > AUDITCMP_OP_STATS ||
	    (msg->flags & ~AUDITCMP_MSG_F_MASK) != 0 ||
	    (role != AUDITCMP_MESSAGE_REPLY && msg->status != 0) ||
	    (role == AUDITCMP_MESSAGE_REPLY &&
	    (msg->status > 0 || msg->status < -ELAST))) {
		errno = EPROTO;
		return (-1);
	}
	return (0);
}

int
auditcmp_message_init(struct auditcmp_msg *msg, uint16_t opcode,
    uint32_t flags)
{

	if (msg == NULL || opcode < AUDITCMP_OP_HELLO ||
	    opcode > AUDITCMP_OP_STATS ||
	    (flags & ~AUDITCMP_MSG_F_MASK) != 0) {
		errno = EINVAL;
		return (-1);
	}
	memset(msg, 0, sizeof(*msg));
	msg->magic = AUDITCMP_MAGIC;
	msg->version = AUDITCMP_ABI_VERSION;
	msg->opcode = opcode;
	return (0);
}

int
auditcmp_message_init_reply(struct auditcmp_msg *reply,
    const struct auditcmp_msg *request, int status)
{

	if (reply == NULL || request == NULL ||
	    header_validate(request, sizeof(*request),
	    AUDITCMP_MESSAGE_REQUEST) == -1 ||
	    status > 0 || status < -ELAST) {
		errno = EINVAL;
		return (-1);
	}
	memset(reply, 0, sizeof(*reply));
	reply->magic = AUDITCMP_MAGIC;
	reply->version = AUDITCMP_ABI_VERSION;
	reply->opcode = request->opcode;
	reply->status = status;
	return (0);
}

int
auditcmp_validate_message(const struct auditcmp_msg *msg, size_t length,
    enum auditcmp_message_role role)
{
	const struct auditcmp_submit_request *submit;
	const struct auditcmp_hello_reply *hello;
	size_t payload;

	if (header_validate(msg, length, role) == -1)
		return (-1);
	payload = length - sizeof(*msg);
	if (role == AUDITCMP_MESSAGE_EVENT)
		goto invalid;
	if (role == AUDITCMP_MESSAGE_REPLY) {
		if (msg->status != 0)
			return (payload == 0 ? 0 : (errno = EPROTO, -1));
		switch (msg->opcode) {
		case AUDITCMP_OP_HELLO:
			if (payload != sizeof(*hello))
				goto invalid;
			hello = (const void *)(msg + 1);
			if (hello->version != AUDITCMP_ABI_VERSION ||
			    hello->reserved[0] != 0 ||
			    hello->reserved[1] != 0 ||
			    hello->reserved[2] != 0)
				goto invalid;
			break;
		case AUDITCMP_OP_STATS:
			if (payload != sizeof(struct auditcmp_stats))
				goto invalid;
			break;
		case AUDITCMP_OP_SUBMIT:
			if (payload != 0)
				goto invalid;
			break;
		}
		return (0);
	}
	switch (msg->opcode) {
	case AUDITCMP_OP_HELLO:
	case AUDITCMP_OP_STATS:
		if (payload != 0)
			goto invalid;
		break;
	case AUDITCMP_OP_SUBMIT:
		if (payload != sizeof(*submit))
			goto invalid;
		submit = (const void *)(msg + 1);
		if (submit->error < 0 || submit->error > ELAST ||
		    submit->reserved != 0 ||
		    !fixed_string_valid(submit->subject,
		    submit->subject_length, sizeof(submit->subject)) ||
		    !fixed_string_valid(submit->operation,
		    submit->operation_length, sizeof(submit->operation)))
			goto invalid;
		break;
	}
	return (0);

invalid:
	errno = EPROTO;
	return (-1);
}

int
auditcmp_validate_fds(const struct auditcmp_msg *msg, size_t nfds,
    enum auditcmp_message_role role)
{

	if (msg == NULL || (role != AUDITCMP_MESSAGE_REQUEST &&
	    role != AUDITCMP_MESSAGE_REPLY &&
	    role != AUDITCMP_MESSAGE_EVENT)) {
		errno = EINVAL;
		return (-1);
	}
	if (nfds != 0) {
		errno = EPROTO;
		return (-1);
	}
	return (0);
}

int
auditcmp_client_prepare(int *fdp)
{
	int error, fd;

	if (fdp == NULL)
		return (errno = EINVAL, -1);
	*fdp = -1;
	fd = -1;
	error = service_open(AUDITCMP_INTERFACE, &fd) == -1 ? errno : 0;
	if (error == 0 &&
	    (cap_xfer_limit(fd, CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(fd, CAP_CLOFORK_ONCE) == -1 ||
	    cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED) == -1))
		error = errno;
	if (error != 0) {
		if (fd >= 0)
			close(fd);
		errno = error;
		return (-1);
	}
	*fdp = fd;
	return (0);
}

static int
call(struct auditcmp_client *client, uint16_t opcode, const void *payload,
    size_t payload_length, union auditcmp_buffer *reply)
{
	union auditcmp_buffer request;
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;
	struct auditcmp_msg *msg;
	size_t length;

	if (client == NULL)
		return (errno = EINVAL, -1);
	if (client->owner != getpid())
		return (errno = ECHILD, -1);
	memset(&request, 0, sizeof(request));
	msg = (void *)request.bytes;
	if (auditcmp_message_init(msg, opcode, 0) == -1)
		return (-1);
	if (payload_length != 0)
		memcpy(msg + 1, payload, payload_length);
	length = sizeof(*msg) + payload_length;
	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = msg;
	outgoing.length = length;
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = reply;
	incoming.capacity = sizeof(*reply);
	options.timeout_ms = 5000;
	if (service_session_call(client->session, &outgoing, &incoming,
	    &options) == -1)
		return (-1);
	msg = (void *)reply->bytes;
	if (incoming.nfds != 0 ||
	    auditcmp_validate_message(msg, incoming.length,
	    AUDITCMP_MESSAGE_REPLY) == -1 || msg->opcode != opcode) {
		(void)service_session_fail(client->session, EPROTO);
		return (errno = EPROTO, -1);
	}
	if (msg->status != 0)
		return (errno = -msg->status, -1);
	return (0);
}

int
auditcmp_client_adopt(int fd, struct auditcmp_client **clientp)
{
	union auditcmp_buffer reply;
	struct auditcmp_client *client;
	int error, owned;

	if (fd < 0 || clientp == NULL)
		return (errno = EINVAL, -1);
	*clientp = NULL;
	owned = fcntl(fd, F_DUPFD_CLOEXEC, 0);
	error = owned == -1 ? errno : 0;
	(void)close(fd);
	if (error != 0)
		return (errno = error, -1);
	client = calloc(1, sizeof(*client));
	if (client == NULL) {
		close(owned);
		return (-1);
	}
	client->owner = getpid();
	if (service_session_create(owned, &client->session) == -1) {
		error = errno;
		close(owned);
		free(client);
		return (errno = error, -1);
	}
	if (call(client, AUDITCMP_OP_HELLO, NULL, 0, &reply) == -1) {
		auditcmp_client_close(client);
		return (-1);
	}
	*clientp = client;
	return (0);
}

int
auditcmp_client_open(struct auditcmp_client **clientp)
{
	int fd;

	if (clientp == NULL)
		return (errno = EINVAL, -1);
	if (auditcmp_client_prepare(&fd) == -1)
		return (-1);
	if (auditcmp_client_adopt(fd, clientp) == -1)
		return (-1);
	return (0);
}

void
auditcmp_client_close(struct auditcmp_client *client)
{

	if (client == NULL)
		return;
	if (client->owner == getpid())
		service_session_close(client->session);
	free(client);
}

int
auditcmp_submit(struct auditcmp_client *client, const char *subject,
    const char *operation, int error)
{
	union auditcmp_buffer reply;
	struct auditcmp_submit_request request;
	size_t subject_length, operation_length;

	if (client == NULL || subject == NULL || operation == NULL ||
	    error < 0 || error > ELAST)
		return (errno = EINVAL, -1);
	subject_length = strnlen(subject, AUDITCMP_MAX_SUBJECT + 1);
	operation_length = strnlen(operation, AUDITCMP_MAX_OPERATION + 1);
	if (subject_length == 0 || subject_length > AUDITCMP_MAX_SUBJECT ||
	    operation_length == 0 ||
	    operation_length > AUDITCMP_MAX_OPERATION)
		return (errno = EINVAL, -1);
	memset(&request, 0, sizeof(request));
	request.error = error;
	request.subject_length = subject_length;
	request.operation_length = operation_length;
	memcpy(request.subject, subject, subject_length);
	memcpy(request.operation, operation, operation_length);
	if (!fixed_string_valid(request.subject, request.subject_length,
	    sizeof(request.subject)) ||
	    !fixed_string_valid(request.operation, request.operation_length,
	    sizeof(request.operation)))
		return (errno = EINVAL, -1);
	return (call(client, AUDITCMP_OP_SUBMIT, &request, sizeof(request),
	    &reply));
}

int
auditcmp_stats(struct auditcmp_client *client, struct auditcmp_stats *stats)
{
	union auditcmp_buffer reply;

	if (stats == NULL)
		return (errno = EINVAL, -1);
	if (call(client, AUDITCMP_OP_STATS, NULL, 0, &reply) == -1)
		return (-1);
	memcpy(stats, (struct auditcmp_msg *)reply.bytes + 1, sizeof(*stats));
	return (0);
}
