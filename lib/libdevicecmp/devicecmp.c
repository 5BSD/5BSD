/*- SPDX-License-Identifier: BSD-2-Clause */
/*
 * system.Device client: open a named /dev leaf and receive a Capsicum-narrowed
 * descriptor.  Mirrors libcryptocmp's socket-free service_session transport; the
 * provider session is opened by name once and cached for the process, guarded by
 * a mutex and re-created after a fork.
 */
#include <sys/types.h>

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

#include <libservice.h>

#include "devicecmp.h"

static pthread_mutex_t devicecmp_lock = PTHREAD_MUTEX_INITIALIZER;
static struct service_session *devicecmp_session;
static pid_t devicecmp_owner;

static bool
valid_status(int32_t status)
{

	return (status <= 0 && status >= -ELAST);
}

static bool
valid_leaf(const char *name)
{
	size_t length;

	if (name == NULL)
		return (false);
	length = strnlen(name, DEVICECMP_MAX_NAME);
	return (length != 0 && length < DEVICECMP_MAX_NAME && name[0] != '.' &&
	    strchr(name, '/') == NULL);
}

static bool
valid_reply_header(const struct devicecmp_msg *msg, uint16_t opcode)
{

	return (msg->magic == DEVICECMP_MAGIC &&
	    msg->version == DEVICECMP_ABI_VERSION && msg->opcode == opcode &&
	    msg->flags == 0 && valid_status(msg->status));
}

/*
 * Return a cached provider session, opening one on first use (or after a fork
 * that orphaned the inherited session).  Caller holds devicecmp_lock.
 */
static int
session_get(struct service_session **out)
{
	struct service_session *session;
	int fd;

	if (devicecmp_session != NULL && devicecmp_owner == getpid()) {
		*out = devicecmp_session;
		return (0);
	}
	if (devicecmp_session != NULL) {
		/* Inherited across fork: drop it and open a fresh one. */
		service_session_close(devicecmp_session);
		devicecmp_session = NULL;
	}
	if (service_open(DEVICECMP_INTERFACE, &fd) == -1)
		return (-1);
	if (service_session_create(fd, &session) == -1) {
		(void)close(fd);
		return (-1);
	}
	devicecmp_session = session;
	devicecmp_owner = getpid();
	*out = session;
	return (0);
}

/*
 * Perform one request/reply over the cached session with the lock held for the
 * whole exchange (the session is process-wide shared state).  Returns 0 on a
 * completed round trip (reply validation is the caller's job), -1 with errno on
 * a transport/open failure.
 */
static int
session_call_locked(const struct service_message *outgoing,
    struct service_reply *incoming, const struct service_call_options *options,
    struct service_session **usedp)
{
	struct service_session *session;
	int result, error;

	*usedp = NULL;
	pthread_mutex_lock(&devicecmp_lock);
	if (session_get(&session) == -1) {
		result = -1;
	} else {
		*usedp = session;
		result = service_session_call(session, outgoing, incoming,
		    options);
	}
	error = errno;
	if (result == -1 && *usedp != NULL && devicecmp_session == *usedp) {
		service_session_close(devicecmp_session);
		devicecmp_session = NULL;
		devicecmp_owner = 0;
	}
	pthread_mutex_unlock(&devicecmp_lock);
	if (result == -1)
		errno = error;
	return (result);
}

/* Close received_fd and poison exactly the session that sent a bad reply. */
static int
protocol_error(struct service_session *used, int received_fd)
{

	if (received_fd >= 0)
		(void)close(received_fd);
	pthread_mutex_lock(&devicecmp_lock);
	if (used != NULL && devicecmp_session == used &&
	    devicecmp_owner == getpid()) {
		(void)service_session_fail(used, EPROTO);
		service_session_close(used);
		devicecmp_session = NULL;
		devicecmp_owner = 0;
	}
	pthread_mutex_unlock(&devicecmp_lock);
	return (errno = EPROTO, -1);
}

int
devicecmp_open(struct service_context *ctx, const char *name,
    uint32_t want_rights, uint32_t *granted_rights, int *fdp)
{
	struct {
		struct devicecmp_msg msg;
		struct devicecmp_open_body body;
		char name[DEVICECMP_MAX_NAME];
	} wire;
	struct {
		struct devicecmp_msg msg;
		struct devicecmp_open_body body;
	} reply;
	struct service_message outgoing;
	struct service_reply incoming;
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_session *used;
	size_t name_length;
	int fd;

	(void)ctx;
	if (fdp == NULL)
		return (errno = EINVAL, -1);
	*fdp = -1;
	if (granted_rights != NULL)
		*granted_rights = 0;
	if (!valid_leaf(name) || want_rights == 0 ||
	    (want_rights & ~DEVICECMP_RIGHT_ALL) != 0)
		return (errno = EINVAL, -1);
	name_length = strlen(name);

	memset(&wire, 0, sizeof(wire));
	wire.msg.magic = DEVICECMP_MAGIC;
	wire.msg.version = DEVICECMP_ABI_VERSION;
	wire.msg.opcode = DEVICECMP_OP_OPEN;
	wire.body.rights = want_rights;
	wire.body.name_length = (uint16_t)(name_length + 1);
	memcpy(wire.name, name, name_length);

	fd = -1;
	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = &wire;
	outgoing.length = sizeof(wire.msg) + sizeof(wire.body) + name_length + 1;
	memset(&reply, 0, sizeof(reply));
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = &reply;
	incoming.capacity = sizeof(reply);
	incoming.fds = &fd;
	incoming.fd_capacity = 1;
	options.timeout_ms = 30000;

	if (session_call_locked(&outgoing, &incoming, &options, &used) == -1)
		return (-1);
	if (!valid_reply_header(&reply.msg, DEVICECMP_OP_OPEN))
		return (protocol_error(used, fd));
	if (reply.msg.status != 0) {
		if (incoming.length != sizeof(reply.msg) || incoming.nfds != 0)
			return (protocol_error(used, fd));
		return (errno = -reply.msg.status, -1);
	}
	if (incoming.length != sizeof(reply) || incoming.nfds != 1 || fd < 0 ||
	    reply.body.name_length != 0 || reply.body.reserved != 0 ||
	    reply.body.rights == 0 ||
	    (reply.body.rights & ~DEVICECMP_RIGHT_ALL) != 0 ||
	    (reply.body.rights & ~want_rights) != 0)
		return (protocol_error(used, fd));
	if (granted_rights != NULL)
		*granted_rights = reply.body.rights;
	*fdp = fd;
	return (0);
}

int
devicecmp_list(struct service_context *ctx, uint32_t cursor,
    struct devicecmp_list_entry *entries, uint32_t max, uint32_t *countp,
    uint32_t *next_cursorp)
{
	struct {
		struct devicecmp_msg msg;
		struct devicecmp_list_request body;
	} wire;
	struct {
		struct devicecmp_msg msg;
		struct devicecmp_list_reply body;
	} reply;
	struct service_message outgoing;
	struct service_reply incoming;
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_session *used;
	uint32_t count, i;

	(void)ctx;
	if (countp != NULL)
		*countp = 0;
	if (next_cursorp != NULL)
		*next_cursorp = 0;
	if (entries == NULL || max == 0)
		return (errno = EINVAL, -1);

	memset(&wire, 0, sizeof(wire));
	wire.msg.magic = DEVICECMP_MAGIC;
	wire.msg.version = DEVICECMP_ABI_VERSION;
	wire.msg.opcode = DEVICECMP_OP_LIST;
	wire.body.cursor = cursor;

	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = &wire;
	outgoing.length = sizeof(wire);
	memset(&reply, 0, sizeof(reply));
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = &reply;
	incoming.capacity = sizeof(reply);
	incoming.fd_capacity = 0;
	options.timeout_ms = 30000;

	if (session_call_locked(&outgoing, &incoming, &options, &used) == -1)
		return (-1);
	if (!valid_reply_header(&reply.msg, DEVICECMP_OP_LIST) ||
	    incoming.nfds != 0)
		return (protocol_error(used, -1));
	if (reply.msg.status != 0) {
		if (incoming.length != sizeof(reply.msg))
			return (protocol_error(used, -1));
		return (errno = -reply.msg.status, -1);
	}
	if (incoming.length != sizeof(reply) || reply.body.reserved[0] != 0 ||
	    reply.body.reserved[1] != 0 ||
	    reply.body.count > DEVICECMP_LIST_MAX ||
	    (reply.body.next_cursor != 0 &&
	    (reply.body.count == 0 || reply.body.next_cursor <= cursor)))
		return (protocol_error(used, -1));
	for (i = 0; i < reply.body.count; i++) {
		const struct devicecmp_list_entry *entry;

		entry = &reply.body.entries[i];
		if (!valid_leaf(entry->name) || entry->rights == 0 ||
		    (entry->rights & ~DEVICECMP_RIGHT_ALL) != 0 ||
		    (entry->flags & ~DEVICECMP_LIST_FLAG_IOCTL_WHITELIST) != 0 ||
		    ((entry->flags & DEVICECMP_LIST_FLAG_IOCTL_WHITELIST) != 0 &&
		    (entry->rights & DEVICECMP_RIGHT_IOCTL) == 0))
			return (protocol_error(used, -1));
	}
	count = reply.body.count;
	if (count > max) {
		if (countp != NULL)
			*countp = count;
		return (errno = ENOMEM, -1);
	}
	memcpy(entries, reply.body.entries,
	    (size_t)count * sizeof(entries[0]));
	if (countp != NULL)
		*countp = count;
	if (next_cursorp != NULL)
		*next_cursorp = reply.body.next_cursor;
	return (0);
}

int
devicecmp_hello(struct service_context *ctx)
{
	struct devicecmp_msg out;
	struct {
		struct devicecmp_msg msg;
		struct devicecmp_hello_reply hello;
	} reply;
	struct service_message outgoing;
	struct service_reply incoming;
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_session *used;

	(void)ctx;
	memset(&out, 0, sizeof(out));
	out.magic = DEVICECMP_MAGIC;
	out.version = DEVICECMP_ABI_VERSION;
	out.opcode = DEVICECMP_OP_HELLO;
	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = &out;
	outgoing.length = sizeof(out);
	memset(&reply, 0, sizeof(reply));
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = &reply;
	incoming.capacity = sizeof(reply);
	incoming.fd_capacity = 0;
	options.timeout_ms = 30000;

	if (session_call_locked(&outgoing, &incoming, &options, &used) == -1)
		return (-1);
	if (!valid_reply_header(&reply.msg, DEVICECMP_OP_HELLO) ||
	    incoming.nfds != 0)
		return (protocol_error(used, -1));
	if (reply.msg.status != 0) {
		if (incoming.length != sizeof(reply.msg))
			return (protocol_error(used, -1));
		return (errno = -reply.msg.status, -1);
	}
	if (incoming.length != sizeof(reply) ||
	    reply.hello.version != DEVICECMP_ABI_VERSION ||
	    reply.hello.reserved[0] != 0 || reply.hello.reserved[1] != 0 ||
	    reply.hello.reserved[2] != 0)
		return (protocol_error(used, -1));
	return (0);
}
