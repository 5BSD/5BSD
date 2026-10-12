/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Retained pre-FIDL system.Sysctl record helpers (sysctlcmp_server.h) for ABI
 * compatibility.  The current client and provider use sysctlcmp.fidl and do
 * not use these; the provider rejects these records.
 */

#include <sys/param.h>

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "sysctlcmp_server.h"

static int
header_validate(const struct sysctlcmp_msg *msg, size_t length,
    enum sysctlcmp_message_role role)
{

	if (msg == NULL || length < sizeof(*msg) ||
	    length > SYSCTLCMP_MAX_MESSAGE ||
	    (role != SYSCTLCMP_MESSAGE_REQUEST &&
	    role != SYSCTLCMP_MESSAGE_REPLY) ||
	    msg->magic != SYSCTLCMP_MAGIC ||
	    msg->opcode < SYSCTLCMP_OP_GET ||
	    msg->opcode > SYSCTLCMP_OP_INTERFACES ||
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

	if (msg == NULL || opcode < SYSCTLCMP_OP_GET ||
	    opcode > SYSCTLCMP_OP_INTERFACES || flags != 0) {
		errno = EINVAL;
		return (-1);
	}
	memset(msg, 0, sizeof(*msg));
	msg->magic = SYSCTLCMP_MAGIC;
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
	/* A rejected reply (status != 0) carries no body. */
	if (role == SYSCTLCMP_MESSAGE_REPLY && msg->status != 0) {
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
	/* Requests name an OID; only NEXT permits the empty root cursor. */
	if (role == SYSCTLCMP_MESSAGE_REQUEST) {
		const char *name = (const char *)(body + 1);

		if (body->name_length == 0 ||
		    name[body->name_length - 1] != '\0' ||
		    (msg->opcode != SYSCTLCMP_OP_NEXT &&
		    body->name_length == 1) ||
		    (msg->opcode != SYSCTLCMP_OP_SET &&
		    body->value_length != 0)) {
			errno = EPROTO;
			return (-1);
		}
	} else if (body->name_length != 0 ||
	    (msg->opcode == SYSCTLCMP_OP_SET && body->value_length != 0)) {
		/* Reply bodies never echo names; SET has no value payload. */
		errno = EPROTO;
		return (-1);
	}
	if (msg->opcode == SYSCTLCMP_OP_INTERFACES) {
		if (role == SYSCTLCMP_MESSAGE_REQUEST) {
			if (body->name_length != sizeof(SYSCTLCMP_INTERFACES_POLICY) ||
			    memcmp(body + 1, SYSCTLCMP_INTERFACES_POLICY,
			    sizeof(SYSCTLCMP_INTERFACES_POLICY)) != 0)
				return (errno = EPROTO, -1);
		} else {
			struct sysctlcmp_interface entry;
			uint32_t last = 0;
			size_t n, i;

			if (body->value_length % sizeof(entry) != 0)
				return (errno = EPROTO, -1);
			n = body->value_length / sizeof(entry);
			for (i = 0; i < n; i++) {
				memcpy(&entry, (const uint8_t *)(body + 1) +
				    i * sizeof(entry), sizeof(entry));
				size_t name_length = strnlen(entry.name, sizeof(entry.name));
				if (entry.index <= last || entry.link_state > SYSCTLCMP_LINK_UP ||
				    memcmp(entry.reserved, (uint8_t[3]){0}, 3) != 0 ||
				    name_length == 0 || name_length == sizeof(entry.name) ||
				    memcmp(entry.name + name_length, (char[SYSCTLCMP_IFNAME_SIZE]){0},
				    sizeof(entry.name) - name_length) != 0)
					return (errno = EPROTO, -1);
				for (size_t j = 0; j < i; j++) {
					struct sysctlcmp_interface previous;
					memcpy(&previous, (const uint8_t *)(body + 1) +
					    j * sizeof(previous), sizeof(previous));
					if (memcmp(entry.name, previous.name, sizeof(entry.name)) == 0)
						return (errno = EPROTO, -1);
				}
				last = entry.index;
			}
		}
	}
	return (0);
}
