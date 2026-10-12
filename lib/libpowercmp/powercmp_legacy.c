/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Kory Heard */
/* Retained pre-FIDL validator for ABI compatibility; not used by the native path. */
#include <errno.h>
#include <stddef.h>

#include "powercmp_protocol.h"

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
