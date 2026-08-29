/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libservice.h>

#include "filesystemcmp.h"
#include "filesystemcmp_server.h"
#include "filesystemcmp_probes.h"

static const char filesystemcmp_dependency_note[]
    __attribute__((section(".note.5bsd.descriptors"), used)) =
    "interface=system.Filesystem\n"
    "version=1.0.0\n"
    "local-name=filesystem\n"
    "required=true\n";

union filesystemcmp_buffer {
	max_align_t align;
	struct {
		struct filesystemcmp_msg msg;
		uint8_t payload[FILESYSTEMCMP_MAX_MESSAGE -
		    sizeof(struct filesystemcmp_msg)];
	} wire;
};

struct filesystemcmp_client {
	struct service_session	*channel;
	pid_t			 owner;
	uint32_t		 references;
	_Atomic int		 terminal_error;
};

static pthread_mutex_t filesystemcmp_registry_lock =
    PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t filesystemcmp_registry_ready =
    PTHREAD_COND_INITIALIZER;
static pthread_once_t filesystemcmp_atfork_once = PTHREAD_ONCE_INIT;
static struct filesystemcmp_client *filesystemcmp_process_client;
static int filesystemcmp_atfork_error;
static bool filesystemcmp_initializing;

static void filesystemcmp_atfork_prepare(void) __no_lock_analysis;
static void filesystemcmp_atfork_parent(void) __no_lock_analysis;
static void filesystemcmp_atfork_child(void) __no_lock_analysis;

static void
filesystemcmp_atfork_prepare(void)
{

	(void)pthread_mutex_lock(&filesystemcmp_registry_lock);
}

static void
filesystemcmp_atfork_parent(void)
{

	(void)pthread_mutex_unlock(&filesystemcmp_registry_lock);
}

static void
filesystemcmp_atfork_child(void)
{

	filesystemcmp_process_client = NULL;
	filesystemcmp_initializing = false;
	(void)pthread_mutex_unlock(&filesystemcmp_registry_lock);
}

static void
filesystemcmp_atfork_init(void)
{

	filesystemcmp_atfork_error = pthread_atfork(
	    filesystemcmp_atfork_prepare, filesystemcmp_atfork_parent,
	    filesystemcmp_atfork_child);
}

static bool
filesystemcmp_wire_name_valid(const void *name, uint32_t length)
{

	return (length != 0 && length <= FILESYSTEMCMP_NAME_MAX &&
	    memchr(name, '\0', length) == NULL &&
	    !(length == 1 && memcmp(name, ".", 1) == 0) &&
	    !(length == 2 && memcmp(name, "..", 2) == 0) &&
	    memchr(name, '/', length) == NULL);
}

static int
filesystemcmp_header_validate(const struct filesystemcmp_msg *msg,
    size_t received, enum filesystemcmp_message_role role)
{

	if (msg == NULL || received < sizeof(*msg) ||
	    received > FILESYSTEMCMP_MAX_MESSAGE ||
	    (role != FILESYSTEMCMP_MESSAGE_REQUEST &&
	    role != FILESYSTEMCMP_MESSAGE_REPLY &&
	    role != FILESYSTEMCMP_MESSAGE_EVENT) ||
	    msg->magic != FILESYSTEMCMP_MAGIC ||
	    msg->version != FILESYSTEMCMP_ABI_VERSION ||
	    msg->opcode < FILESYSTEMCMP_OP_HELLO ||
	    msg->opcode > FILESYSTEMCMP_OP_DUP ||
	    (msg->flags & ~FILESYSTEMCMP_MSG_F_MASK) != 0 ||
	    (role != FILESYSTEMCMP_MESSAGE_REPLY && msg->status != 0) ||
	    (role == FILESYSTEMCMP_MESSAGE_REPLY &&
	    (msg->status > 0 || msg->status < -ELAST))) {
		errno = EPROTO;
		return (-1);
	}
	return (0);
}

int
filesystemcmp_message_init(struct filesystemcmp_msg *msg, uint16_t opcode,
    uint32_t flags)
{

	if (msg == NULL || opcode < FILESYSTEMCMP_OP_HELLO ||
	    opcode > FILESYSTEMCMP_OP_DUP ||
	    (flags & ~FILESYSTEMCMP_MSG_F_MASK) != 0) {
		errno = EINVAL;
		return (-1);
	}
	memset(msg, 0, sizeof(*msg));
	msg->magic = FILESYSTEMCMP_MAGIC;
	msg->version = FILESYSTEMCMP_ABI_VERSION;
	msg->opcode = opcode;
	msg->flags = flags;
	return (0);
}

int
filesystemcmp_message_init_reply(struct filesystemcmp_msg *reply,
    const struct filesystemcmp_msg *request, int status)
{

	if (reply == NULL || request == NULL ||
	    filesystemcmp_header_validate(request, sizeof(*request),
	    FILESYSTEMCMP_MESSAGE_REQUEST) == -1 ||
	    status > 0 || status < -ELAST) {
		errno = EINVAL;
		return (-1);
	}
	memset(reply, 0, sizeof(*reply));
	reply->magic = FILESYSTEMCMP_MAGIC;
	reply->version = FILESYSTEMCMP_ABI_VERSION;
	reply->opcode = request->opcode;
	reply->status = status;
	return (0);
}

int
filesystemcmp_open(struct filesystemcmp_client **clientp)
    __no_lock_analysis
{
	struct filesystemcmp_client *client;
	struct service_context *service;
	int error, fd;

	if (clientp == NULL) {
		errno = EINVAL;
		return (-1);
	}
	*clientp = NULL;
	error = pthread_once(&filesystemcmp_atfork_once,
	    filesystemcmp_atfork_init);
	if (error == 0)
		error = filesystemcmp_atfork_error;
	if (error == 0)
		error = pthread_mutex_lock(&filesystemcmp_registry_lock);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	while (filesystemcmp_initializing) {
		error = pthread_cond_wait(&filesystemcmp_registry_ready,
		    &filesystemcmp_registry_lock);
		if (error != 0) {
			(void)pthread_mutex_unlock(
			    &filesystemcmp_registry_lock);
			errno = error;
			return (-1);
		}
	}
	if (filesystemcmp_process_client != NULL) {
		filesystemcmp_process_client->references++;
		*clientp = filesystemcmp_process_client;
		(void)pthread_mutex_unlock(&filesystemcmp_registry_lock);
		return (0);
	}
	filesystemcmp_initializing = true;
	(void)pthread_mutex_unlock(&filesystemcmp_registry_lock);
	client = calloc(1, sizeof(*client));
	if (client == NULL)
		goto fail_create;
	if (service_acquire(&service) == -1)
		goto fail_create;
	if (service_local_component_open(service, FILESYSTEMCMP_INTERFACE,
	    FILESYSTEMCMP_INTERFACE_VERSION, &fd) == -1) {
		error = errno;
		service_release(service);
		errno = error;
		goto fail_create;
	}
	service_release(service);
	if (service_session_create(fd, &client->channel) == -1) {
		error = errno;
		close(fd);
		errno = error;
		goto fail_create;
	}
	client->owner = getpid();
	client->references = 1;
	error = pthread_mutex_lock(&filesystemcmp_registry_lock);
	if (error != 0) {
		service_session_close(client->channel);
		free(client);
		errno = error;
		return (-1);
	}
	filesystemcmp_process_client = client;
	filesystemcmp_initializing = false;
	*clientp = client;
	(void)pthread_cond_broadcast(&filesystemcmp_registry_ready);
	(void)pthread_mutex_unlock(&filesystemcmp_registry_lock);
	FILESYSTEMCMP_PROBE_OPEN(__DECONST(char *, FILESYSTEMCMP_INTERFACE), 0);
	return (0);

fail_create:
	error = errno;
	free(client);
	if (pthread_mutex_lock(&filesystemcmp_registry_lock) == 0) {
		filesystemcmp_initializing = false;
		(void)pthread_cond_broadcast(&filesystemcmp_registry_ready);
		(void)pthread_mutex_unlock(&filesystemcmp_registry_lock);
	}
	FILESYSTEMCMP_PROBE_OPEN(__DECONST(char *, FILESYSTEMCMP_INTERFACE),
	    error);
	errno = error;
	return (-1);
}

void
filesystemcmp_close(struct filesystemcmp_client *client)
    __no_lock_analysis
{
	if (client == NULL)
		return;
	if (pthread_mutex_lock(&filesystemcmp_registry_lock) != 0)
		return;
	if (client != filesystemcmp_process_client ||
	    client->owner != getpid() || client->references == 0) {
		(void)pthread_mutex_unlock(&filesystemcmp_registry_lock);
		return;
	}
	if (--client->references != 0) {
		(void)pthread_mutex_unlock(&filesystemcmp_registry_lock);
		return;
	}
	/*
	 * The injected component channel is process-lifetime authority.
	 * Retain its sole managed reader at zero public borrows so a later
	 * open can reacquire it without racing a second reader on the same
	 * kernel channel or requiring ambient rediscovery.
	 */
	(void)pthread_mutex_unlock(&filesystemcmp_registry_lock);
}

int
filesystemcmp_validate_message(const struct filesystemcmp_msg *msg,
    size_t received, enum filesystemcmp_message_role role)
{
	size_t payload, expected;
	uint16_t probe_opcode;

	probe_opcode = msg != NULL ? msg->opcode : 0;
	if (filesystemcmp_header_validate(msg, received, role) == -1)
		goto reject;
	payload = received - sizeof(*msg);
	if (role == FILESYSTEMCMP_MESSAGE_EVENT)
		goto reject;
	if (role == FILESYSTEMCMP_MESSAGE_REPLY && msg->status != 0)
		expected = 0;
	else if (role == FILESYSTEMCMP_MESSAGE_REPLY) {
		switch (msg->opcode) {
		case FILESYSTEMCMP_OP_HELLO: {
			const struct filesystemcmp_hello_reply *hello;

			expected = sizeof(struct filesystemcmp_hello_reply);
			if (payload == expected) {
				hello = (const void *)(msg + 1);
				if (hello->version != FILESYSTEMCMP_ABI_VERSION ||
				    (hello->features &
				    ~(FILESYSTEMCMP_FEATURE_INLINE_IO |
				    FILESYSTEMCMP_FEATURE_PERSISTENT |
				    FILESYSTEMCMP_FEATURE_BUNDLE)) != 0)
					goto reject;
			}
			break;
		}
		case FILESYSTEMCMP_OP_OPEN_ROOT:
		case FILESYSTEMCMP_OP_OPEN_NAMESPACE:
		case FILESYSTEMCMP_OP_LOOKUP:
		case FILESYSTEMCMP_OP_OPEN:
		case FILESYSTEMCMP_OP_DUP:
		case FILESYSTEMCMP_OP_CREATE: {
			const struct filesystemcmp_handle_reply *handle;

			expected = sizeof(struct filesystemcmp_handle_reply);
			if (payload == expected) {
				handle = (const void *)(msg + 1);
				if (handle->reserved != 0 ||
				    handle->type < FILESYSTEMCMP_TYPE_REGULAR ||
				    handle->type >
				    FILESYSTEMCMP_TYPE_DIRECTORY)
					goto reject;
			}
			break;
		}
		case FILESYSTEMCMP_OP_READ: {
			if (payload < sizeof(struct filesystemcmp_io_reply))
				goto reject;
			const struct filesystemcmp_io_reply *io_reply;

			io_reply = (const void *)(msg + 1);
			if (io_reply->reserved != 0 ||
			    io_reply->length > FILESYSTEMCMP_INLINE_MAX)
				goto reject;
			expected = sizeof(*io_reply) + io_reply->length;
			break;
		}
		case FILESYSTEMCMP_OP_WRITE: {
			const struct filesystemcmp_io_reply *io_reply;

			expected = sizeof(struct filesystemcmp_io_reply);
			if (payload == expected) {
				io_reply = (const void *)(msg + 1);
				if (io_reply->reserved != 0 ||
				    io_reply->length > FILESYSTEMCMP_INLINE_MAX)
					goto reject;
			}
			break;
		}
		case FILESYSTEMCMP_OP_STAT: {
			const struct filesystemcmp_stat_reply *stat_reply;

			expected = sizeof(struct filesystemcmp_stat_reply);
			if (payload == expected) {
				stat_reply = (const void *)(msg + 1);
				if (stat_reply->type <
				    FILESYSTEMCMP_TYPE_REGULAR ||
				    stat_reply->type >
				    FILESYSTEMCMP_TYPE_DIRECTORY)
					goto reject;
			}
			break;
		}
		default:
			expected = 0;
			break;
		}
	} else {
		switch (msg->opcode) {
		case FILESYSTEMCMP_OP_HELLO: {
			const struct filesystemcmp_hello *hello;

			expected = sizeof(struct filesystemcmp_hello);
			if (payload == expected) {
				hello = (const void *)(msg + 1);
				if (hello->reserved != 0 ||
				    hello->min_version > hello->max_version ||
				    hello->min_version >
				    FILESYSTEMCMP_ABI_VERSION ||
				    hello->max_version <
				    FILESYSTEMCMP_ABI_VERSION ||
				    (hello->features &
				    ~(FILESYSTEMCMP_FEATURE_INLINE_IO |
				    FILESYSTEMCMP_FEATURE_PERSISTENT |
				    FILESYSTEMCMP_FEATURE_BUNDLE)) != 0)
					goto reject;
			}
			break;
		}
		case FILESYSTEMCMP_OP_OPEN_ROOT:
			expected = 0;
			break;
		case FILESYSTEMCMP_OP_OPEN_NAMESPACE: {
			const struct filesystemcmp_namespace_request *request;

			expected = sizeof(*request);
			if (payload == expected) {
				request = (const void *)(msg + 1);
				if (request->namespace <
				    FILESYSTEMCMP_NAMESPACE_SCRATCH ||
				    request->namespace >
				    FILESYSTEMCMP_NAMESPACE_BUNDLE ||
				    request->reserved != 0)
					goto reject;
			}
			break;
		}
		case FILESYSTEMCMP_OP_LOOKUP:
			if (payload < sizeof(struct filesystemcmp_lookup_request))
				goto reject;
			const struct filesystemcmp_lookup_request *lookup;

			lookup = (const void *)(msg + 1);
			expected = sizeof(*lookup) + lookup->name_length;
			if (payload == expected &&
			    (lookup->flags != 0 ||
			    !filesystemcmp_wire_name_valid(lookup + 1,
			    lookup->name_length)))
				goto reject;
			break;
		case FILESYSTEMCMP_OP_OPEN: {
			const struct filesystemcmp_open_request *open;

			expected = sizeof(struct filesystemcmp_open_request);
			if (payload == expected) {
				open = (const void *)(msg + 1);
				if (open->reserved != 0 ||
				    (open->flags & ~FILESYSTEMCMP_OPEN_MASK) != 0)
					goto reject;
			}
			break;
		}
		case FILESYSTEMCMP_OP_CREATE:
			if (payload < sizeof(struct filesystemcmp_create_request))
				goto reject;
			const struct filesystemcmp_create_request *create;

			create = (const void *)(msg + 1);
			expected = sizeof(*create) + create->name_length;
			if (payload == expected &&
			    (create->reserved != 0 ||
			    (create->flags & ~FILESYSTEMCMP_CREATE_MASK) != 0 ||
			    !filesystemcmp_wire_name_valid(create + 1,
			    create->name_length)))
				goto reject;
			break;
		case FILESYSTEMCMP_OP_READ: {
			const struct filesystemcmp_io_request *io;

			expected = sizeof(struct filesystemcmp_io_request);
			if (payload == expected) {
				io = (const void *)(msg + 1);
				if (io->flags != 0 ||
				    io->length > FILESYSTEMCMP_INLINE_MAX)
					goto reject;
			}
			break;
		}
		case FILESYSTEMCMP_OP_WRITE:
			if (payload < sizeof(struct filesystemcmp_io_request))
				goto reject;
			const struct filesystemcmp_io_request *io;

			io = (const void *)(msg + 1);
			expected = sizeof(*io) + io->length;
			if (payload == expected &&
			    (io->flags != 0 ||
			    io->length > FILESYSTEMCMP_INLINE_MAX))
				goto reject;
			break;
		case FILESYSTEMCMP_OP_STAT:
		case FILESYSTEMCMP_OP_CLOSE:
		case FILESYSTEMCMP_OP_SYNC:
		case FILESYSTEMCMP_OP_DUP:
			expected = sizeof(struct filesystemcmp_close_request);
			break;
		case FILESYSTEMCMP_OP_UNLINK:
			if (payload < sizeof(struct filesystemcmp_unlink_request))
				goto reject;
			const struct filesystemcmp_unlink_request *unlink;

			unlink = (const void *)(msg + 1);
			expected = sizeof(*unlink) + unlink->name_length;
			if (payload == expected &&
			    (unlink->flags != 0 ||
			    !filesystemcmp_wire_name_valid(unlink + 1,
			    unlink->name_length)))
				goto reject;
			break;
		case FILESYSTEMCMP_OP_RENAME:
			if (payload < sizeof(struct filesystemcmp_rename_request))
				goto reject;
			const struct filesystemcmp_rename_request *rename;
			const char *old_name, *new_name;

			rename = (const void *)(msg + 1);
			expected = sizeof(*rename) + rename->old_name_length +
			    rename->new_name_length;
			old_name = (const void *)(rename + 1);
			new_name = old_name + rename->old_name_length;
			if (payload == expected &&
			    (rename->reserved != 0 || rename->flags != 0 ||
			    !filesystemcmp_wire_name_valid(old_name,
			    rename->old_name_length) ||
			    !filesystemcmp_wire_name_valid(new_name,
			    rename->new_name_length)))
				goto reject;
			break;
		default:
			goto reject;
		}
	}
	if (expected > FILESYSTEMCMP_MAX_MESSAGE - sizeof(*msg) ||
	    payload != expected)
		goto reject;
	return (0);

reject:
	errno = EPROTO;
	FILESYSTEMCMP_PROBE_REJECT(probe_opcode, (uint32_t)received, EPROTO);
	return (-1);
}

int
filesystemcmp_validate_fds(const struct filesystemcmp_msg *msg, size_t nfds,
    enum filesystemcmp_message_role role)
{
	if (msg == NULL || (role != FILESYSTEMCMP_MESSAGE_REQUEST &&
	    role != FILESYSTEMCMP_MESSAGE_REPLY &&
	    role != FILESYSTEMCMP_MESSAGE_EVENT)) {
		errno = EINVAL;
		return (-1);
	}
	if (nfds != 0) {
		errno = EPROTO;
		return (-1);
	}
	return (0);
}

static int filesystemcmp_rpc(struct filesystemcmp_client *, uint16_t,
    const void *, size_t,
    union filesystemcmp_buffer *, size_t *) __no_lock_analysis;

static int
filesystemcmp_rpc(struct filesystemcmp_client *client, uint16_t opcode,
    const void *payload, size_t payload_length,
    union filesystemcmp_buffer *reply, size_t *reply_length)
{
	union filesystemcmp_buffer request;
	struct service_call_options options =
	    SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;
	struct filesystemcmp_msg *msg;
	size_t received, request_length;
	int terminal_error;

	if (client == NULL || client->owner != getpid() ||
	    client->channel == NULL || payload_length >
	    FILESYSTEMCMP_MAX_MESSAGE - sizeof(struct filesystemcmp_msg) ||
	    (payload_length != 0 && payload == NULL)) {
		errno = EINVAL;
		return (-1);
	}
	terminal_error = atomic_load(&client->terminal_error);
	if (terminal_error != 0)
		return (errno = terminal_error, -1);
	memset(&request, 0, sizeof(request));
	msg = &request.wire.msg;
	if (filesystemcmp_message_init(msg, opcode, 0) == -1)
		return (-1);
	if (payload_length != 0)
		memcpy(msg + 1, payload, payload_length);
	request_length = sizeof(*msg) + payload_length;
	FILESYSTEMCMP_PROBE_SEND(opcode, (uint32_t)request_length, 0, 0);
	memset(&outgoing, 0, sizeof(outgoing));
	outgoing.size = sizeof(outgoing);
	outgoing.data = msg;
	outgoing.length = request_length;
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = reply;
	incoming.capacity = sizeof(*reply);
	options.timeout_ms = 30000;
	if (service_session_call(client->channel, &outgoing, &incoming,
	    &options) == -1) {
		FILESYSTEMCMP_PROBE_REJECT(opcode, 0, errno);
		return (-1);
	}
	received = incoming.length;
	msg = &reply->wire.msg;
	if (incoming.nfds != 0 ||
	    filesystemcmp_validate_message(msg, received,
	    FILESYSTEMCMP_MESSAGE_REPLY) == -1 ||
	    filesystemcmp_validate_fds(msg, incoming.nfds,
	    FILESYSTEMCMP_MESSAGE_REPLY) == -1 || msg->opcode != opcode) {
		errno = EPROTO;
		atomic_store(&client->terminal_error, EPROTO);
		FILESYSTEMCMP_PROBE_REJECT(opcode, (uint32_t)received, EPROTO);
		return (-1);
	}
	FILESYSTEMCMP_PROBE_RECEIVE(opcode, (uint32_t)received,
	    (uint32_t)incoming.nfds, 0);
	if (msg->status != 0) {
		errno = -msg->status;
		return (-1);
	}
	*reply_length = (size_t)received;
	return (0);
}

static bool
filesystemcmp_name_valid(const char *name, size_t *length)
{
	size_t n;

	if (name == NULL)
		return (false);
	n = strlen(name);
	if (n == 0 || n > FILESYSTEMCMP_NAME_MAX ||
	    strcmp(name, ".") == 0 || strcmp(name, "..") == 0 ||
	    strchr(name, '/') != NULL)
		return (false);
	*length = n;
	return (true);
}

int
filesystemcmp_hello(struct filesystemcmp_client *client,
    struct filesystemcmp_hello_reply *reply_value)
{
	union filesystemcmp_buffer reply;
	struct filesystemcmp_hello request;
	size_t length;

	if (reply_value == NULL) {
		errno = EINVAL;
		return (-1);
	}
	memset(&request, 0, sizeof(request));
	request.min_version = FILESYSTEMCMP_ABI_VERSION;
	request.max_version = FILESYSTEMCMP_ABI_VERSION;
	request.features = FILESYSTEMCMP_FEATURE_INLINE_IO |
	    FILESYSTEMCMP_FEATURE_PERSISTENT |
	    FILESYSTEMCMP_FEATURE_BUNDLE;
	if (filesystemcmp_rpc(client, FILESYSTEMCMP_OP_HELLO, &request,
	    sizeof(request), &reply, &length) == -1)
		return (-1);
	memcpy(reply_value, &reply.wire.msg + 1, sizeof(*reply_value));
	return (0);
}

int
filesystemcmp_open_root(struct filesystemcmp_client *client,
    struct filesystemcmp_handle *root)
{
	union filesystemcmp_buffer reply;
	const struct filesystemcmp_handle_reply *result;
	size_t length;

	if (root == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (filesystemcmp_rpc(client, FILESYSTEMCMP_OP_OPEN_ROOT, NULL, 0,
	    &reply, &length) == -1)
		return (-1);
	result = (const void *)(&reply.wire.msg + 1);
	if (result->type != FILESYSTEMCMP_TYPE_DIRECTORY) {
		errno = EPROTO;
		return (-1);
	}
	*root = result->handle;
	return (0);
}

int
filesystemcmp_open_namespace(struct filesystemcmp_client *client,
    uint32_t namespace_id,
    struct filesystemcmp_handle *root)
{
	union filesystemcmp_buffer reply;
	struct filesystemcmp_namespace_request request;
	const struct filesystemcmp_handle_reply *result;
	size_t length;

	if (root == NULL ||
	    namespace_id < FILESYSTEMCMP_NAMESPACE_SCRATCH ||
	    namespace_id > FILESYSTEMCMP_NAMESPACE_BUNDLE) {
		errno = EINVAL;
		return (-1);
	}
	memset(&request, 0, sizeof(request));
	request.namespace = namespace_id;
	if (filesystemcmp_rpc(client, FILESYSTEMCMP_OP_OPEN_NAMESPACE, &request,
	    sizeof(request), &reply, &length) == -1)
		return (-1);
	result = (const void *)(&reply.wire.msg + 1);
	if (result->type != FILESYSTEMCMP_TYPE_DIRECTORY) {
		errno = EPROTO;
		return (-1);
	}
	*root = result->handle;
	return (0);
}

int
filesystemcmp_lookup(struct filesystemcmp_client *client,
    struct filesystemcmp_handle directory,
    const char *name, struct filesystemcmp_handle_reply *reply_value)
{
	union filesystemcmp_buffer request, reply;
	struct filesystemcmp_lookup_request *lookup;
	size_t name_length, length;

	if (reply_value == NULL ||
	    !filesystemcmp_name_valid(name, &name_length)) {
		errno = EINVAL;
		return (-1);
	}
	memset(&request, 0, sizeof(request));
	lookup = (void *)request.wire.payload;
	lookup->directory = directory;
	lookup->name_length = (uint32_t)name_length;
	memcpy(lookup + 1, name, name_length);
	if (filesystemcmp_rpc(client, FILESYSTEMCMP_OP_LOOKUP, lookup,
	    sizeof(*lookup) + name_length, &reply, &length) == -1)
		return (-1);
	memcpy(reply_value, &reply.wire.msg + 1, sizeof(*reply_value));
	return (0);
}

int
filesystemcmp_open_handle(struct filesystemcmp_client *client,
    struct filesystemcmp_handle object,
    uint32_t flags, struct filesystemcmp_handle_reply *reply_value)
{
	union filesystemcmp_buffer reply;
	struct filesystemcmp_open_request request;
	size_t length;

	if (reply_value == NULL || (flags & ~FILESYSTEMCMP_OPEN_MASK) != 0) {
		errno = EINVAL;
		return (-1);
	}
	memset(&request, 0, sizeof(request));
	request.object = object;
	request.flags = flags;
	if (filesystemcmp_rpc(client, FILESYSTEMCMP_OP_OPEN, &request,
	    sizeof(request), &reply, &length) == -1)
		return (-1);
	memcpy(reply_value, &reply.wire.msg + 1, sizeof(*reply_value));
	return (0);
}

int
filesystemcmp_create(struct filesystemcmp_client *client,
    struct filesystemcmp_handle directory,
    const char *name, uint32_t flags, uint32_t mode,
    struct filesystemcmp_handle_reply *reply_value)
{
	union filesystemcmp_buffer request, reply;
	struct filesystemcmp_create_request *create;
	size_t name_length, length;

	if (reply_value == NULL ||
	    !filesystemcmp_name_valid(name, &name_length) ||
	    (flags & ~FILESYSTEMCMP_CREATE_MASK) != 0) {
		errno = EINVAL;
		return (-1);
	}
	memset(&request, 0, sizeof(request));
	create = (void *)request.wire.payload;
	create->directory = directory;
	create->name_length = (uint32_t)name_length;
	create->flags = flags;
	create->mode = mode;
	memcpy(create + 1, name, name_length);
	if (filesystemcmp_rpc(client, FILESYSTEMCMP_OP_CREATE, create,
	    sizeof(*create) + name_length, &reply, &length) == -1)
		return (-1);
	memcpy(reply_value, &reply.wire.msg + 1, sizeof(*reply_value));
	return (0);
}

ssize_t
filesystemcmp_pread(struct filesystemcmp_client *client,
    struct filesystemcmp_handle object, void *buffer, size_t length,
    uint64_t offset)
{
	union filesystemcmp_buffer reply;
	struct filesystemcmp_io_request request;
	const struct filesystemcmp_io_reply *result;
	size_t reply_length;

	if ((buffer == NULL && length != 0) ||
	    length > FILESYSTEMCMP_INLINE_MAX) {
		errno = EINVAL;
		return (-1);
	}
	memset(&request, 0, sizeof(request));
	request.object = object;
	request.offset = offset;
	request.length = (uint32_t)length;
	if (filesystemcmp_rpc(client, FILESYSTEMCMP_OP_READ, &request,
	    sizeof(request), &reply, &reply_length) == -1)
		return (-1);
	result = (const void *)(&reply.wire.msg + 1);
	if (result->length > length) {
		errno = EPROTO;
		return (-1);
	}
	memcpy(buffer, result + 1, result->length);
	return ((ssize_t)result->length);
}

ssize_t
filesystemcmp_pwrite(struct filesystemcmp_client *client,
    struct filesystemcmp_handle object,
    const void *buffer, size_t length, uint64_t offset)
{
	union filesystemcmp_buffer request, reply;
	struct filesystemcmp_io_request *io;
	const struct filesystemcmp_io_reply *result;
	size_t reply_length;

	if ((buffer == NULL && length != 0) ||
	    length > FILESYSTEMCMP_INLINE_MAX) {
		errno = EINVAL;
		return (-1);
	}
	memset(&request, 0, sizeof(request));
	io = (void *)request.wire.payload;
	io->object = object;
	io->offset = offset;
	io->length = (uint32_t)length;
	memcpy(io + 1, buffer, length);
	if (filesystemcmp_rpc(client, FILESYSTEMCMP_OP_WRITE, io,
	    sizeof(*io) + length, &reply, &reply_length) == -1)
		return (-1);
	result = (const void *)(&reply.wire.msg + 1);
	if (result->length > length) {
		errno = EPROTO;
		return (-1);
	}
	return ((ssize_t)result->length);
}

int
filesystemcmp_stat(struct filesystemcmp_client *client,
    struct filesystemcmp_handle object,
    struct filesystemcmp_stat_reply *reply_value)
{
	union filesystemcmp_buffer reply;
	struct filesystemcmp_close_request request;
	size_t length;

	if (reply_value == NULL) {
		errno = EINVAL;
		return (-1);
	}
	memset(&request, 0, sizeof(request));
	request.object = object;
	if (filesystemcmp_rpc(client, FILESYSTEMCMP_OP_STAT, &request,
	    sizeof(request), &reply, &length) == -1)
		return (-1);
	memcpy(reply_value, &reply.wire.msg + 1, sizeof(*reply_value));
	return (0);
}

int
filesystemcmp_unlink(struct filesystemcmp_client *client,
    struct filesystemcmp_handle directory,
    const char *name, uint32_t flags)
{
	union filesystemcmp_buffer request, reply;
	struct filesystemcmp_unlink_request *unlink_request;
	size_t name_length, length;

	if (!filesystemcmp_name_valid(name, &name_length)) {
		errno = EINVAL;
		return (-1);
	}
	memset(&request, 0, sizeof(request));
	unlink_request = (void *)request.wire.payload;
	unlink_request->directory = directory;
	unlink_request->name_length = (uint32_t)name_length;
	unlink_request->flags = flags;
	memcpy(unlink_request + 1, name, name_length);
	return (filesystemcmp_rpc(client, FILESYSTEMCMP_OP_UNLINK,
	    unlink_request, sizeof(*unlink_request) + name_length, &reply,
	    &length));
}

int
filesystemcmp_rename(struct filesystemcmp_client *client,
    struct filesystemcmp_handle old_directory,
    const char *old_name, struct filesystemcmp_handle new_directory,
    const char *new_name, uint32_t flags)
{
	union filesystemcmp_buffer request, reply;
	struct filesystemcmp_rename_request *rename_request;
	size_t old_length, new_length, length;
	char *names;

	if (!filesystemcmp_name_valid(old_name, &old_length) ||
	    !filesystemcmp_name_valid(new_name, &new_length)) {
		errno = EINVAL;
		return (-1);
	}
	memset(&request, 0, sizeof(request));
	rename_request = (void *)request.wire.payload;
	rename_request->old_directory = old_directory;
	rename_request->new_directory = new_directory;
	rename_request->old_name_length = (uint32_t)old_length;
	rename_request->new_name_length = (uint32_t)new_length;
	rename_request->flags = flags;
	names = (char *)(rename_request + 1);
	memcpy(names, old_name, old_length);
	memcpy(names + old_length, new_name, new_length);
	return (filesystemcmp_rpc(client, FILESYSTEMCMP_OP_RENAME,
	    rename_request, sizeof(*rename_request) + old_length + new_length,
	    &reply, &length));
}

int
filesystemcmp_close_handle(struct filesystemcmp_client *client,
    struct filesystemcmp_handle object)
{
	union filesystemcmp_buffer reply;
	struct filesystemcmp_close_request request;
	size_t length;

	memset(&request, 0, sizeof(request));
	request.object = object;
	return (filesystemcmp_rpc(client, FILESYSTEMCMP_OP_CLOSE, &request,
	    sizeof(request), &reply, &length));
}

int
filesystemcmp_sync(struct filesystemcmp_client *client,
    struct filesystemcmp_handle object)
{
	union filesystemcmp_buffer reply;
	struct filesystemcmp_close_request request;
	size_t length;

	memset(&request, 0, sizeof(request));
	request.object = object;
	return (filesystemcmp_rpc(client, FILESYSTEMCMP_OP_SYNC, &request,
	    sizeof(request), &reply, &length));
}

int
filesystemcmp_dup(struct filesystemcmp_client *client,
    struct filesystemcmp_handle object,
    struct filesystemcmp_handle_reply *reply_value)
{
	union filesystemcmp_buffer reply;
	struct filesystemcmp_close_request request;
	size_t length;

	if (reply_value == NULL) {
		errno = EINVAL;
		return (-1);
	}
	memset(&request, 0, sizeof(request));
	request.object = object;
	if (filesystemcmp_rpc(client, FILESYSTEMCMP_OP_DUP, &request,
	    sizeof(request), &reply, &length) == -1)
		return (-1);
	memcpy(reply_value, &reply.wire.msg + 1, sizeof(*reply_value));
	return (0);
}
