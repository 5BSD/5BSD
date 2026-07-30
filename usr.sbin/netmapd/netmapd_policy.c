/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "netmapd_policy.h"

int
netmapd_validate_message(const struct netmap_bearer_msg *message,
    size_t received, size_t nfds)
{
	size_t expected;
	bool reply;

	if (message == NULL || received < sizeof(*message) ||
	    received > NETMAP_BEARER_MAX_MESSAGE ||
	    message->magic != NETMAP_BEARER_MAGIC ||
	    message->version != NETMAP_BEARER_VERSION ||
	    message->opcode < NETMAP_BEARER_OP_HELLO ||
	    message->opcode > NETMAP_BEARER_OP_REPLACE_POLICY ||
	    (message->flags & ~NETMAP_BEARER_MSG_F_REPLY) != 0 ||
	    message->reserved != 0 || message->length != received) {
		errno = EPROTO;
		return (-1);
	}
	reply = (message->flags & NETMAP_BEARER_MSG_F_REPLY) != 0;
	if ((!reply && message->status != 0) ||
	    (reply && message->status > 0)) {
		errno = EPROTO;
		return (-1);
	}
	if (reply && message->status != 0)
		expected = 0;
	else if (reply && message->opcode == NETMAP_BEARER_OP_CREATE)
		expected = sizeof(struct netmap_bearer_reply);
	else if (!reply && message->opcode == NETMAP_BEARER_OP_CREATE)
		expected = sizeof(struct netmap_bearer_create);
	else
		expected = 0;
	if (received - sizeof(*message) != expected ||
	    nfds != (reply && message->status == 0 &&
	    message->opcode == NETMAP_BEARER_OP_CREATE ? 1 : 0)) {
		errno = EPROTO;
		return (-1);
	}
	return (0);
}

int
netmapd_validate_create(const struct netmap_bearer_create *request)
{
	size_t length, i;

	if (request == NULL ||
	    request->type != NETMAP_BEARER_VALE ||
	    request->queue_first != 0 ||
	    request->queue_count > 1 ||
	    request->slots > 65536 ||
	    request->buffer_size != 0 ||
	    (request->flags & ~(NETMAP_BEARER_F_RX |
	    NETMAP_BEARER_F_TX)) != 0 ||
	    (request->flags & (NETMAP_BEARER_F_RX |
	    NETMAP_BEARER_F_TX)) == 0) {
		errno = EPERM;
		return (-1);
	}
	length = strnlen(request->interface, sizeof(request->interface));
	if (length == sizeof(request->interface) || length < 7 ||
	    strncmp(request->interface, "vale", 4) != 0 ||
	    strchr(request->interface, ':') == NULL) {
		errno = EINVAL;
		return (-1);
	}
	for (i = 0; i < length; i++) {
		if (!isalnum((unsigned char)request->interface[i]) &&
		    request->interface[i] != ':' &&
		    request->interface[i] != '_') {
			errno = EINVAL;
			return (-1);
		}
	}
	return (0);
}
