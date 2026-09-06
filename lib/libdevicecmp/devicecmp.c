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
    struct service_reply *incoming, const struct service_call_options *options)
{
	struct service_session *session;
	int result, error;

	pthread_mutex_lock(&devicecmp_lock);
	if (session_get(&session) == -1)
		result = -1;
	else
		result = service_session_call(session, outgoing, incoming,
		    options);
	error = errno;
	pthread_mutex_unlock(&devicecmp_lock);
	if (result == -1)
		errno = error;
	return (result);
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
	size_t name_length;
	int fd;

	(void)ctx;
	if (fdp == NULL)
		return (errno = EINVAL, -1);
	*fdp = -1;
	if (granted_rights != NULL)
		*granted_rights = 0;
	if (name == NULL || want_rights == 0 ||
	    (want_rights & ~DEVICECMP_RIGHT_ALL) != 0)
		return (errno = EINVAL, -1);
	name_length = strnlen(name, DEVICECMP_MAX_NAME);
	if (name_length == 0 || name_length >= DEVICECMP_MAX_NAME)
		return (errno = EINVAL, -1);

	memset(&wire, 0, sizeof(wire));
	wire.msg.magic = DEVICECMP_MAGIC;
	wire.msg.version = DEVICECMP_ABI_VERSION;
	wire.msg.opcode = DEVICECMP_OP_OPEN;
	wire.body.rights = want_rights;
	wire.body.name_length = (uint16_t)(name_length + 1);
	memcpy(wire.name, name, name_length);	/* trailing NUL already zeroed */

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

	if (session_call_locked(&outgoing, &incoming, &options) == -1)
		return (-1);

	if (incoming.length != sizeof(reply) ||
	    reply.msg.magic != DEVICECMP_MAGIC ||
	    reply.msg.version != DEVICECMP_ABI_VERSION ||
	    reply.msg.opcode != DEVICECMP_OP_OPEN ||
	    !valid_status(reply.msg.status) ||
	    incoming.nfds != (reply.msg.status == 0 ? 1 : 0)) {
		if (incoming.nfds != 0 && fd >= 0)
			(void)close(fd);
		return (errno = EPROTO, -1);
	}
	if (reply.msg.status != 0)
		return (errno = -reply.msg.status, -1);
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
	uint32_t count;

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

	if (session_call_locked(&outgoing, &incoming, &options) == -1)
		return (-1);

	/*
	 * Strict, fail-closed reply validation.  A success reply carries the
	 * full body; an error reply is header-only (the daemon does not amplify
	 * a rejected request into a full-size list buffer), so accept either the
	 * full length or a bare header, and require the header-only form to carry
	 * a nonzero (error) status.
	 */
	if (reply.msg.magic != DEVICECMP_MAGIC ||
	    reply.msg.version != DEVICECMP_ABI_VERSION ||
	    reply.msg.opcode != DEVICECMP_OP_LIST ||
	    !valid_status(reply.msg.status) || incoming.nfds != 0)
		return (errno = EPROTO, -1);
	if (incoming.length == sizeof(struct devicecmp_msg)) {
		if (reply.msg.status == 0)
			return (errno = EPROTO, -1);
		return (errno = -reply.msg.status, -1);
	}
	if (incoming.length != sizeof(reply))
		return (errno = EPROTO, -1);
	if (reply.msg.status != 0)
		return (errno = -reply.msg.status, -1);
	count = reply.body.count;
	if (count > DEVICECMP_LIST_MAX)
		return (errno = EPROTO, -1);
	if (count > max)
		count = max;
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

	if (session_call_locked(&outgoing, &incoming, &options) == -1)
		return (-1);

	if (incoming.length != sizeof(reply) ||
	    reply.msg.magic != DEVICECMP_MAGIC ||
	    reply.msg.version != DEVICECMP_ABI_VERSION ||
	    reply.msg.opcode != DEVICECMP_OP_HELLO ||
	    !valid_status(reply.msg.status) || incoming.nfds != 0)
		return (errno = EPROTO, -1);
	if (reply.msg.status != 0)
		return (errno = -reply.msg.status, -1);
	return (0);
}
