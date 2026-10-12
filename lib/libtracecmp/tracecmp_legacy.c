/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Retained pre-FIDL system.Trace record helpers (tracecmp_server.h) for ABI
 * compatibility.  The current client and provider use tracecmp.fidl and do
 * not use these; the provider rejects these records.
 */

#include <sys/param.h>

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "tracecmp_server.h"

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
		if ((hello->features & ~TRACECMP_FEATURE_RAW_DTRACE_FD) != 0 ||
		    hello->reserved != 0)
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
