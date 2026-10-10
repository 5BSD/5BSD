/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Kory Heard */
/* Retained ABI-1 validator for pre-FIDL consumers; not used by the native path. */
#include "timecmp_protocol.h"

int
timecmp_validate_message(const struct timecmp_msg *msg, size_t length,
    enum timecmp_message_role role)
{

	if (msg == NULL || length < sizeof(*msg))
		return (-1);
	if (msg->magic != TIMECMP_MAGIC)
		return (-1);
	if (msg->flags != 0)		/* reserved header field, must be zero */
		return (-1);
	if (length != sizeof(*msg) &&
	    length != sizeof(*msg) + sizeof(struct timecmp_time))
		return (-1);
	switch (msg->opcode) {
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

