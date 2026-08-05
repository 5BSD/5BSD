/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <sys/param.h>

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libservice.h>

#include "kldmgr.h"
#include "kldmgr_server.h"

struct kldmgr_client {
	struct service_session *session;
	pid_t owner;
};

static int
header_valid(const struct kldmgr_msg *msg, size_t length, bool reply)
{

	if (msg == NULL || length < sizeof(*msg) ||
	    length > KLDMGR_MAX_MESSAGE || msg->magic != KLDMGR_MAGIC ||
	    msg->version != KLDMGR_ABI_VERSION ||
	    msg->opcode < KLDMGR_OP_LOAD || msg->opcode > KLDMGR_OP_LIST ||
	    msg->flags != 0 || (!reply && msg->status != 0) ||
	    (reply && (msg->status > 0 || msg->status < -ELAST))) {
		errno = EPROTO;
		return (-1);
	}
	return (0);
}

int
kldmgr_validate_request(const struct kldmgr_msg *msg, size_t length)
{
	const struct kldmgr_module_request *request;
	size_t payload;

	if (header_valid(msg, length, false) == -1)
		return (-1);
	payload = length - sizeof(*msg);
	if (msg->opcode == KLDMGR_OP_LIST)
		return (payload == 0 ? 0 : (errno = EPROTO, -1));
	if (payload != sizeof(*request)) {
		errno = EPROTO;
		return (-1);
	}
	request = (const void *)(msg + 1);
	if (strnlen(request->name, sizeof(request->name)) ==
	    sizeof(request->name) || request->name[0] == '\0') {
		errno = EPROTO;
		return (-1);
	}
	return (0);
}

int
kldmgr_validate_reply(const struct kldmgr_msg *msg, size_t length)
{
	const struct kldmgr_id_reply *id_reply;
	const struct kldmgr_list_entry *entry;
	const struct kldmgr_list_reply *list;
	size_t payload, expected, i;

	if (header_valid(msg, length, true) == -1)
		return (-1);
	payload = length - sizeof(*msg);
	if (msg->status != 0)
		return (payload == 0 ? 0 : (errno = EPROTO, -1));
	if (msg->opcode == KLDMGR_OP_LOAD || msg->opcode == KLDMGR_OP_UNLOAD) {
		if (payload != sizeof(*id_reply))
			return (errno = EPROTO, -1);
		id_reply = (const void *)(msg + 1);
		return (id_reply->id >= 0 && id_reply->reserved == 0 ? 0 :
		    (errno = EPROTO, -1));
	}
	if (payload < sizeof(*list)) {
		errno = EPROTO;
		return (-1);
	}
	list = (const void *)(msg + 1);
	if (list->reserved != 0 || list->count > KLDMGR_LIST_MAX) {
		errno = EPROTO;
		return (-1);
	}
	expected = sizeof(*list) +
	    (size_t)list->count * sizeof(struct kldmgr_list_entry);
	if (payload != expected) {
		errno = EPROTO;
		return (-1);
	}
	for (i = 0; i < list->count; i++) {
		entry = &list->entries[i];
		if (entry->id < 0 || entry->name[0] == '\0' ||
		    strnlen(entry->name, sizeof(entry->name)) ==
		    sizeof(entry->name)) {
			errno = EPROTO;
			return (-1);
		}
	}
	return (0);
}

static int
call(struct kldmgr_client *client, uint16_t opcode, const void *payload,
    size_t payload_length, void *reply_buffer, size_t reply_capacity,
    size_t *reply_length)
{
	struct {
		struct kldmgr_msg header;
		struct kldmgr_module_request payload;
	} request_buffer;
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;
	struct kldmgr_msg *request, *reply;

	if (client == NULL || client->owner != getpid()) {
		errno = client == NULL ? EINVAL : ECHILD;
		return (-1);
	}
	memset(&request_buffer, 0, sizeof(request_buffer));
	request = &request_buffer.header;
	request->magic = KLDMGR_MAGIC;
	request->version = KLDMGR_ABI_VERSION;
	request->opcode = opcode;
	if (payload_length != 0)
		memcpy(request + 1, payload, payload_length);
	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = request;
	outgoing.length = sizeof(*request) + payload_length;
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = reply_buffer;
	incoming.capacity = reply_capacity;
	options.timeout_ms = 30000;
	if (service_session_call(client->session, &outgoing, &incoming,
	    &options) == -1)
		return (-1);
	reply = reply_buffer;
	if (incoming.nfds != 0 ||
	    kldmgr_validate_reply(reply, incoming.length) == -1 ||
	    reply->opcode != opcode) {
		(void)service_session_fail(client->session, EPROTO);
		return (errno = EPROTO, -1);
	}
	if (reply->status != 0)
		return (errno = -reply->status, -1);
	if (reply_length != NULL)
		*reply_length = incoming.length;
	return (0);
}

int
kldmgr_client_open(struct kldmgr_client **clientp)
{
	struct service_context *context;
	struct kldmgr_client *client;
	int fd, error;

	if (clientp == NULL)
		return (errno = EINVAL, -1);
	*clientp = NULL;
	if (service_acquire(&context) == -1)
		return (-1);
	error = service_connect(context, KLDMGR_INTERFACE, &fd) == -1 ?
	    errno : 0;
	service_release(context);
	if (error != 0)
		return (errno = error, -1);
	client = calloc(1, sizeof(*client));
	if (client == NULL) {
		error = errno;
		close(fd);
		return (errno = error, -1);
	}
	if (service_session_create(fd, &client->session) == -1) {
		error = errno;
		close(fd);
		free(client);
		return (errno = error, -1);
	}
	client->owner = getpid();
	*clientp = client;
	return (0);
}

void
kldmgr_client_close(struct kldmgr_client *client)
{

	if (client == NULL)
		return;
	if (client->owner == getpid())
		service_session_close(client->session);
	free(client);
}

static int
module_op(struct kldmgr_client *client, uint16_t opcode, const char *name,
    int *id)
{
	struct {
		struct kldmgr_msg header;
		struct kldmgr_id_reply payload;
	} reply_buffer;
	struct kldmgr_module_request request;

	memset(&request, 0, sizeof(request));
	if (name == NULL || strlcpy(request.name, name,
	    sizeof(request.name)) >= sizeof(request.name))
		return (errno = EINVAL, -1);
	if (call(client, opcode, &request, sizeof(request), &reply_buffer,
	    sizeof(reply_buffer), NULL) == -1)
		return (-1);
	if (id != NULL)
		*id = reply_buffer.payload.id;
	return (0);
}

int
kldmgr_load(struct kldmgr_client *client, const char *name, int *id)
{

	return (module_op(client, KLDMGR_OP_LOAD, name, id));
}

int
kldmgr_unload(struct kldmgr_client *client, const char *name, int *id)
{

	return (module_op(client, KLDMGR_OP_UNLOAD, name, id));
}

int
kldmgr_list(struct kldmgr_client *client, struct kldmgr_list_entry *entries,
    size_t capacity, size_t *count)
{
	struct {
		struct kldmgr_msg header;
		struct {
			uint32_t count;
			uint32_t reserved;
			struct kldmgr_list_entry entries[KLDMGR_LIST_MAX];
		} payload;
	} reply_buffer;

	if (count == NULL || (capacity != 0 && entries == NULL))
		return (errno = EINVAL, -1);
	if (call(client, KLDMGR_OP_LIST, NULL, 0, &reply_buffer,
	    sizeof(reply_buffer), NULL) == -1)
		return (-1);
	if (reply_buffer.payload.count > capacity)
		return (errno = EOVERFLOW, -1);
	if (reply_buffer.payload.count != 0)
		memcpy(entries, reply_buffer.payload.entries,
		    (size_t)reply_buffer.payload.count * sizeof(*entries));
	*count = reply_buffer.payload.count;
	return (0);
}
