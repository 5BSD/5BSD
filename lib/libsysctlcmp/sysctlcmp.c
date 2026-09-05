/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Client library for the system.Sysctl capability: read and (policy
 * permitting) write kernel sysctl variables by name through the provider,
 * instead of calling sysctl(3) directly or forking a Casper cap_sysctl helper.
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

#include "sysctlcmp.h"
#include "sysctlcmp_server.h"

union sysctlcmp_buffer {
	max_align_t align;
	uint8_t bytes[SYSCTLCMP_MAX_MESSAGE];
};

struct sysctlcmp_client {
	struct service_session	*session;
	pid_t			 owner;
};

static int
header_validate(const struct sysctlcmp_msg *msg, size_t length,
    enum sysctlcmp_message_role role)
{

	if (msg == NULL || length < sizeof(*msg) ||
	    length > SYSCTLCMP_MAX_MESSAGE ||
	    (role != SYSCTLCMP_MESSAGE_REQUEST &&
	    role != SYSCTLCMP_MESSAGE_REPLY) ||
	    msg->magic != SYSCTLCMP_MAGIC ||
	    msg->version != SYSCTLCMP_ABI_VERSION ||
	    msg->opcode < SYSCTLCMP_OP_HELLO ||
	    msg->opcode > SYSCTLCMP_OP_NEXT ||
	    msg->flags != 0 ||
	    (role != SYSCTLCMP_MESSAGE_REPLY && msg->status != 0) ||
	    (role == SYSCTLCMP_MESSAGE_REPLY &&
	    (msg->status > 0 || msg->status < -ELAST))) {
		errno = EPROTO;
		return (-1);
	}
	return (0);
}

int
sysctlcmp_message_init(struct sysctlcmp_msg *msg, uint16_t opcode,
    uint32_t flags)
{

	if (msg == NULL || opcode < SYSCTLCMP_OP_HELLO ||
	    opcode > SYSCTLCMP_OP_NEXT || flags != 0) {
		errno = EINVAL;
		return (-1);
	}
	memset(msg, 0, sizeof(*msg));
	msg->magic = SYSCTLCMP_MAGIC;
	msg->version = SYSCTLCMP_ABI_VERSION;
	msg->opcode = opcode;
	return (0);
}

int
sysctlcmp_message_init_reply(struct sysctlcmp_msg *reply,
    const struct sysctlcmp_msg *request, int status)
{

	if (reply == NULL || request == NULL ||
	    header_validate(request, sizeof(*request),
	    SYSCTLCMP_MESSAGE_REQUEST) == -1 ||
	    status > 0 || status < -ELAST) {
		errno = EINVAL;
		return (-1);
	}
	memset(reply, 0, sizeof(*reply));
	reply->magic = SYSCTLCMP_MAGIC;
	reply->version = SYSCTLCMP_ABI_VERSION;
	reply->opcode = request->opcode;
	reply->status = status;
	return (0);
}

int
sysctlcmp_validate_message(const struct sysctlcmp_msg *msg, size_t length,
    enum sysctlcmp_message_role role)
{
	const struct sysctlcmp_body *body;

	if (header_validate(msg, length, role) == -1)
		return (-1);
	/* HELLO carries no body; a rejected reply (status != 0) carries none. */
	if (msg->opcode == SYSCTLCMP_OP_HELLO ||
	    (role == SYSCTLCMP_MESSAGE_REPLY && msg->status != 0)) {
		if (length != sizeof(*msg)) {
			errno = EPROTO;
			return (-1);
		}
		return (0);
	}
	if (length < sizeof(*msg) + sizeof(*body)) {
		errno = EPROTO;
		return (-1);
	}
	body = (const void *)((const uint8_t *)msg + sizeof(*msg));
	if (body->reserved != 0 ||
	    body->name_length > SYSCTLCMP_MAX_NAME ||
	    body->value_length > SYSCTLCMP_MAX_VALUE ||
	    (size_t)sizeof(*msg) + sizeof(*body) + body->name_length +
	    body->value_length != length) {
		errno = EPROTO;
		return (-1);
	}
	/* A request always names something; the name is NUL-terminated. */
	if (role == SYSCTLCMP_MESSAGE_REQUEST) {
		const char *name = (const char *)(body + 1);

		if (body->name_length == 0 ||
		    name[body->name_length - 1] != '\0') {
			errno = EPROTO;
			return (-1);
		}
	}
	return (0);
}

/*
 * Issue one request and validate the reply.  request/req_len is the fully
 * built message; on success reply holds the reply and *reply_len its length.
 */
static int
call(struct sysctlcmp_client *client, const void *request, size_t req_len,
    union sysctlcmp_buffer *reply, size_t *reply_len)
{
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;
	const struct sysctlcmp_msg *rmsg;

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
	rmsg = (const void *)reply->bytes;
	if (incoming.nfds != 0 ||
	    sysctlcmp_validate_message(rmsg, incoming.length,
	    SYSCTLCMP_MESSAGE_REPLY) == -1) {
		(void)service_session_fail(client->session, EPROTO);
		return (errno = EPROTO, -1);
	}
	if (rmsg->status != 0)
		return (errno = -rmsg->status, -1);
	if (reply_len != NULL)
		*reply_len = incoming.length;
	return (0);
}

static int
build_request(union sysctlcmp_buffer *buf, uint16_t opcode, const char *name,
    const void *value, size_t value_len, size_t *req_len)
{
	struct sysctlcmp_msg *msg;
	struct sysctlcmp_body *body;
	size_t name_len;
	uint8_t *p;

	if (name == NULL) {
		errno = EINVAL;
		return (-1);
	}
	name_len = strnlen(name, SYSCTLCMP_MAX_NAME) + 1;
	if (name_len > SYSCTLCMP_MAX_NAME || value_len > SYSCTLCMP_MAX_VALUE) {
		errno = EINVAL;
		return (-1);
	}
	memset(buf, 0, sizeof(*buf));
	msg = (void *)buf->bytes;
	if (sysctlcmp_message_init(msg, opcode, 0) == -1)
		return (-1);
	body = (void *)(msg + 1);
	body->name_length = (uint16_t)name_len;
	body->value_length = (uint32_t)value_len;
	p = (uint8_t *)(body + 1);
	memcpy(p, name, name_len);
	if (value_len != 0)
		memcpy(p + name_len, value, value_len);
	*req_len = sizeof(*msg) + sizeof(*body) + name_len + value_len;
	return (0);
}

/* Shared read-side op: send a name-only request and copy the value reply. */
static int
read_value_op(struct sysctlcmp_client *client, uint16_t opcode,
    const char *name, void *buf, size_t *lenp)
{
	union sysctlcmp_buffer request, reply;
	const struct sysctlcmp_body *body;
	size_t req_len;

	if (client == NULL || lenp == NULL || (buf == NULL && *lenp != 0)) {
		errno = EINVAL;
		return (-1);
	}
	if (build_request(&request, opcode, name, NULL, 0, &req_len) == -1)
		return (-1);
	if (call(client, request.bytes, req_len, &reply, NULL) == -1)
		return (-1);
	body = (const void *)(reply.bytes + sizeof(struct sysctlcmp_msg));
	if (body->value_length > *lenp) {
		*lenp = body->value_length;
		errno = ENOMEM;
		return (-1);
	}
	memcpy(buf, (const uint8_t *)(body + 1) + body->name_length,
	    body->value_length);
	*lenp = body->value_length;
	return (0);
}

int
sysctlcmp_get(struct sysctlcmp_client *client, const char *name, void *buf,
    size_t *lenp)
{

	return (read_value_op(client, SYSCTLCMP_OP_GET, name, buf, lenp));
}

int
sysctlcmp_describe(struct sysctlcmp_client *client, const char *name,
    char *buf, size_t *lenp)
{

	return (read_value_op(client, SYSCTLCMP_OP_DESCR, name, buf, lenp));
}

int
sysctlcmp_next(struct sysctlcmp_client *client, const char *name,
    char *buf, size_t *lenp)
{

	/* An empty name starts enumeration from the root. */
	return (read_value_op(client, SYSCTLCMP_OP_NEXT,
	    name != NULL ? name : "", buf, lenp));
}

int
sysctlcmp_oidfmt(struct sysctlcmp_client *client, const char *name,
    unsigned int *kindp, char *fmt, size_t *fmtlenp)
{
	uint8_t raw[sizeof(struct sysctlcmp_oidfmt) + SYSCTLCMP_MAX_NAME];
	const struct sysctlcmp_oidfmt *of;
	size_t rawlen, fmtlen;

	if (kindp == NULL || fmtlenp == NULL ||
	    (fmt == NULL && *fmtlenp != 0)) {
		errno = EINVAL;
		return (-1);
	}
	rawlen = sizeof(raw);
	if (read_value_op(client, SYSCTLCMP_OP_OIDFMT, name, raw, &rawlen) == -1)
		return (-1);
	if (rawlen < sizeof(*of)) {
		errno = EPROTO;
		return (-1);
	}
	of = (const void *)raw;
	*kindp = of->kind;
	fmtlen = rawlen - sizeof(*of);		/* includes trailing NUL */
	if (fmtlen > *fmtlenp) {
		*fmtlenp = fmtlen;
		errno = ENOMEM;
		return (-1);
	}
	memcpy(fmt, of->fmt, fmtlen);
	*fmtlenp = fmtlen;
	return (0);
}

int
sysctlcmp_set(struct sysctlcmp_client *client, const char *name,
    const void *value, size_t len)
{
	union sysctlcmp_buffer request, reply;
	size_t req_len;

	if (client == NULL || (value == NULL && len != 0)) {
		errno = EINVAL;
		return (-1);
	}
	if (build_request(&request, SYSCTLCMP_OP_SET, name, value, len,
	    &req_len) == -1)
		return (-1);
	return (call(client, request.bytes, req_len, &reply, NULL));
}

int
sysctlcmp_client_open(struct sysctlcmp_client **clientp)
{
	union sysctlcmp_buffer request, reply;
	struct sysctlcmp_client *client;
	struct sysctlcmp_msg *msg;
	size_t req_len;
	int error, fd, owned;

	if (clientp == NULL)
		return (errno = EINVAL, -1);
	*clientp = NULL;
	fd = -1;
	if (service_open(SYSCTLCMP_INTERFACE, &fd) == -1)
		return (-1);
	if (cap_xfer_limit(fd, CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(fd, CAP_CLOFORK_ONCE) == -1 ||
	    cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED) == -1) {
		error = errno;
		close(fd);
		return (errno = error, -1);
	}
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
	memset(&request, 0, sizeof(request));
	msg = (void *)request.bytes;
	if (sysctlcmp_message_init(msg, SYSCTLCMP_OP_HELLO, 0) == -1) {
		error = errno;
		sysctlcmp_client_close(client);
		return (errno = error, -1);
	}
	req_len = sizeof(*msg);
	if (call(client, request.bytes, req_len, &reply, NULL) == -1) {
		error = errno;
		sysctlcmp_client_close(client);
		return (errno = error, -1);
	}
	*clientp = client;
	return (0);
}

void
sysctlcmp_client_close(struct sysctlcmp_client *client)
{

	if (client == NULL)
		return;
	if (client->owner == getpid())
		service_session_close(client->session);
	free(client);
}
