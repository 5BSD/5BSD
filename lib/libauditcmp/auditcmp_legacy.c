/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * The pre-FIDL system.Audit record helpers (auditcmp_server.h).  The current
 * client and provider speak auditcmp.fidl; they still use
 * auditcmp_validate_message() on a locally built submit record, so the field
 * rules (lengths, character set, NUL padding, error range) stay identical,
 * but these records never travel on the wire.
 */

#include <sys/param.h>

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "auditcmp_server.h"

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
		/*
		 * Audit subjects are service labels, which are compound and
		 * carry '/' (e.g. "system.Network/bsdnetwork").  Permit it
		 * alongside the identifier characters; the subject is the
		 * unforgeable, kernel-stamped label, never client-supplied text.
		 */
		if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		    (c >= '0' && c <= '9') || c == '.' || c == '_' ||
		    c == '-' || c == '/')
			continue;
		return (false);
	}
	/*
	 * The padding past the string must be all-NUL.  Check it byte-by-byte
	 * rather than memcmp against a fixed-size zero literal: this helper is
	 * called with capacity == AUDITCMP_MAX_SUBJECT and == AUDITCMP_MAX_OPERATION,
	 * so a literal sized to one would be read out of bounds if the other grew.
	 */
	for (; i < capacity; i++)
		if (text[i] != '\0')
			return (false);
	return (true);
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
	    msg->opcode < AUDITCMP_OP_SUBMIT ||
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

	if (msg == NULL || opcode < AUDITCMP_OP_SUBMIT ||
	    opcode > AUDITCMP_OP_STATS ||
	    (flags & ~AUDITCMP_MSG_F_MASK) != 0) {
		errno = EINVAL;
		return (-1);
	}
	memset(msg, 0, sizeof(*msg));
	msg->magic = AUDITCMP_MAGIC;
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
	reply->opcode = request->opcode;
	reply->status = status;
	return (0);
}

int
auditcmp_validate_message(const struct auditcmp_msg *msg, size_t length,
    enum auditcmp_message_role role)
{
	const struct auditcmp_submit_request *submit;
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
