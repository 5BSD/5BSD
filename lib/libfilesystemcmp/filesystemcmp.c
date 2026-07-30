/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libservice.h>

#include "filesystemcmp.h"
#include "filesystemcmp_probes.h"

static const char filesystemcmp_dependency_note[]
    __attribute__((section(".note.5bsd.components"), used)) =
    "interface=org.5bsd.cmp.filesystem\n"
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

static _Atomic uint64_t filesystemcmp_next_request = 1;
static pthread_mutex_t filesystemcmp_rpc_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t filesystemcmp_atfork_once = PTHREAD_ONCE_INIT;
static int filesystemcmp_atfork_error;

static void filesystemcmp_atfork_prepare(void) __no_lock_analysis;
static void filesystemcmp_atfork_release(void) __no_lock_analysis;

static void
filesystemcmp_atfork_prepare(void)
{

	(void)pthread_mutex_lock(&filesystemcmp_rpc_lock);
}

static void
filesystemcmp_atfork_release(void)
{

	(void)pthread_mutex_unlock(&filesystemcmp_rpc_lock);
}

static void
filesystemcmp_atfork_init(void)
{

	filesystemcmp_atfork_error = pthread_atfork(
	    filesystemcmp_atfork_prepare, filesystemcmp_atfork_release,
	    filesystemcmp_atfork_release);
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

int
filesystemcmp_open(const char *component)
{
	int fd, error;

	if (component == NULL) {
		component = getenv(FILESYSTEMCMP_ENV);
		if (component == NULL)
			component = "filesystem";
	}
	if (component[0] == '\0') {
		errno = EINVAL;
		FILESYSTEMCMP_PROBE_OPEN("", EINVAL);
		return (-1);
	}
	fd = service_component_fd(component);
	if (fd >= 0)
		fd = fcntl(fd, F_DUPFD_CLOEXEC, 0);
	error = fd == -1 ? errno : 0;
	FILESYSTEMCMP_PROBE_OPEN(component, error);
	return (fd);
}

int
filesystemcmp_validate_message(const struct filesystemcmp_msg *msg,
    size_t received)
{
	size_t payload, expected;
	uint16_t probe_opcode;
	bool reply;

	probe_opcode = msg != NULL ? msg->opcode : 0;
	if (msg == NULL || received < sizeof(*msg) ||
	    msg->magic != FILESYSTEMCMP_MAGIC ||
	    msg->version != FILESYSTEMCMP_ABI_VERSION ||
	    msg->opcode < FILESYSTEMCMP_OP_HELLO ||
	    msg->opcode > FILESYSTEMCMP_OP_NOTIFY ||
	    (msg->flags & ~FILESYSTEMCMP_MSG_F_MASK) != 0 ||
	    msg->reserved != 0 ||
	    msg->length != received || msg->length > FILESYSTEMCMP_MAX_MESSAGE) {
		goto reject;
	}
	reply = (msg->flags & FILESYSTEMCMP_MSG_F_REPLY) != 0;
	if ((msg->opcode != FILESYSTEMCMP_OP_NOTIFY &&
	    msg->request_id == 0) ||
	    (!reply && msg->status != 0) ||
	    (reply && (msg->status > 0 || msg->status < -ELAST)))
		goto reject;
	payload = received - sizeof(*msg);
	if (reply && msg->status != 0)
		expected = 0;
	else if (reply) {
		switch (msg->opcode) {
		case FILESYSTEMCMP_OP_HELLO: {
			const struct filesystemcmp_hello_reply *hello;

			expected = sizeof(struct filesystemcmp_hello_reply);
			if (payload == expected) {
				hello = (const void *)(msg + 1);
				if (hello->version != FILESYSTEMCMP_ABI_VERSION ||
				    (hello->features &
				    ~(FILESYSTEMCMP_FEATURE_INLINE_IO |
				    FILESYSTEMCMP_FEATURE_SHM_RINGS)) != 0)
					goto reject;
			}
			break;
		}
		case FILESYSTEMCMP_OP_OPEN_ROOT:
		case FILESYSTEMCMP_OP_LOOKUP:
		case FILESYSTEMCMP_OP_OPEN:
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
				    FILESYSTEMCMP_FEATURE_SHM_RINGS)) != 0)
					goto reject;
			}
			break;
		}
		case FILESYSTEMCMP_OP_OPEN_ROOT:
		case FILESYSTEMCMP_OP_NOTIFY:
			expected = 0;
			break;
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
		case FILESYSTEMCMP_OP_ATTACH_RINGS: {
			const struct filesystemcmp_ring_request *rings;

			expected = sizeof(struct filesystemcmp_ring_request);
			if (payload == expected) {
				rings = (const void *)(msg + 1);
				if (rings->tx_entries == 0 ||
				    rings->rx_entries == 0 ||
				    rings->entry_size == 0 || rings->flags != 0)
					goto reject;
			}
			break;
		}
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
filesystemcmp_validate_fds(const struct filesystemcmp_msg *msg, size_t nfds)
{
	size_t expected;

	if (msg == NULL) {
		errno = EINVAL;
		return (-1);
	}
	expected = msg->opcode == FILESYSTEMCMP_OP_ATTACH_RINGS &&
	    (msg->flags & FILESYSTEMCMP_MSG_F_REPLY) == 0 ? 8 : 0;
	if (nfds != expected) {
		errno = EPROTO;
		return (-1);
	}
	return (0);
}

int
filesystemcmp_send_message(int fd, const void *message, size_t length,
    const int *fds, size_t nfds)
{
	const struct filesystemcmp_msg *msg;

	if (message == NULL || length < sizeof(*msg)) {
		errno = EINVAL;
		return (-1);
	}
	msg = message;
	if (filesystemcmp_validate_message(msg, length) == -1)
		return (-1);
	if (filesystemcmp_validate_fds(msg, nfds) == -1)
		return (-1);
	int result, probe_error;

	result = service_send_fds(fd, message, length, fds, nfds);
	probe_error = result == -1 ? errno : 0;
	FILESYSTEMCMP_PROBE_SEND(msg->opcode, (uint32_t)length,
	    (uint32_t)nfds, probe_error);
	return (result);
}

ssize_t
filesystemcmp_receive_message(int fd, void *message, size_t capacity,
    int *fds, size_t *nfds)
{
	ssize_t received;
	size_t i, received_fds;

	if (message == NULL || capacity < sizeof(struct filesystemcmp_msg) ||
	    capacity > FILESYSTEMCMP_MAX_MESSAGE) {
		errno = EINVAL;
		return (-1);
	}
	received = service_recv_fds(fd, message, capacity, fds, nfds);
	if (received == -1)
		return (-1);
	received_fds = nfds != NULL ? *nfds : 0;
	if (filesystemcmp_validate_message(message, (size_t)received) == -1 ||
	    filesystemcmp_validate_fds(message, received_fds) == -1) {
		for (i = 0; i < received_fds; i++) {
			if (fds != NULL && fds[i] >= 0) {
				close(fds[i]);
				fds[i] = -1;
			}
		}
		if (nfds != NULL)
			*nfds = 0;
		return (-1);
	}
	FILESYSTEMCMP_PROBE_RECEIVE(
	    ((struct filesystemcmp_msg *)message)->opcode,
	    (uint32_t)received, (uint32_t)(nfds != NULL ? *nfds : 0), 0);
	return (received);
}

static int filesystemcmp_rpc(int, uint16_t, const void *, size_t,
    union filesystemcmp_buffer *, size_t *) __no_lock_analysis;

static int
filesystemcmp_rpc(int fd, uint16_t opcode, const void *payload,
    size_t payload_length, union filesystemcmp_buffer *reply,
    size_t *reply_length)
{
	union filesystemcmp_buffer request;
	struct filesystemcmp_msg *msg;
	size_t nfds;
	ssize_t received;
	uint64_t request_id;
	int error, result;

	if (fd < 0 || payload_length >
	    FILESYSTEMCMP_MAX_MESSAGE - sizeof(struct filesystemcmp_msg) ||
	    (payload_length != 0 && payload == NULL)) {
		errno = EINVAL;
		return (-1);
	}
	error = pthread_once(&filesystemcmp_atfork_once,
	    filesystemcmp_atfork_init);
	if (error == 0)
		error = filesystemcmp_atfork_error;
	if (error != 0) {
		errno = error;
		return (-1);
	}
	error = pthread_mutex_lock(&filesystemcmp_rpc_lock);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	result = -1;
	memset(&request, 0, sizeof(request));
	msg = &request.wire.msg;
	msg->magic = FILESYSTEMCMP_MAGIC;
	msg->version = FILESYSTEMCMP_ABI_VERSION;
	msg->opcode = opcode;
	msg->length = sizeof(*msg) + payload_length;
	request_id = atomic_fetch_add_explicit(&filesystemcmp_next_request, 1,
	    memory_order_relaxed);
	if (request_id == 0)
		request_id = atomic_fetch_add_explicit(
		    &filesystemcmp_next_request, 1, memory_order_relaxed);
	msg->request_id = request_id;
	if (payload_length != 0)
		memcpy(msg + 1, payload, payload_length);
	if (filesystemcmp_send_message(fd, msg, msg->length, NULL, 0) == -1)
		goto out;
	for (;;) {
		nfds = 0;
		received = filesystemcmp_receive_message(fd, reply, sizeof(*reply),
		    NULL, &nfds);
		if (received == -1)
			goto out;
		msg = &reply->wire.msg;
		if ((msg->flags & FILESYSTEMCMP_MSG_F_REPLY) == 0 &&
		    msg->opcode == FILESYSTEMCMP_OP_NOTIFY)
			continue;
		if ((msg->flags & FILESYSTEMCMP_MSG_F_REPLY) == 0 ||
		    msg->opcode != opcode || msg->request_id != request_id) {
			errno = EPROTO;
			goto out;
		}
		if (msg->status != 0) {
			errno = -msg->status;
			goto out;
		}
		*reply_length = (size_t)received;
		result = 0;
		break;
	}
out:
	error = errno;
	(void)pthread_mutex_unlock(&filesystemcmp_rpc_lock);
	errno = error;
	return (result);
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
filesystemcmp_hello(int fd, struct filesystemcmp_hello_reply *reply_value)
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
	    FILESYSTEMCMP_FEATURE_SHM_RINGS;
	if (filesystemcmp_rpc(fd, FILESYSTEMCMP_OP_HELLO, &request,
	    sizeof(request), &reply, &length) == -1)
		return (-1);
	memcpy(reply_value, &reply.wire.msg + 1, sizeof(*reply_value));
	return (0);
}

int
filesystemcmp_open_root(int fd, struct filesystemcmp_handle *root)
{
	union filesystemcmp_buffer reply;
	const struct filesystemcmp_handle_reply *result;
	size_t length;

	if (root == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (filesystemcmp_rpc(fd, FILESYSTEMCMP_OP_OPEN_ROOT, NULL, 0, &reply,
	    &length) == -1)
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
filesystemcmp_lookup(int fd, struct filesystemcmp_handle directory,
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
	if (filesystemcmp_rpc(fd, FILESYSTEMCMP_OP_LOOKUP, lookup,
	    sizeof(*lookup) + name_length, &reply, &length) == -1)
		return (-1);
	memcpy(reply_value, &reply.wire.msg + 1, sizeof(*reply_value));
	return (0);
}

int
filesystemcmp_open_handle(int fd, struct filesystemcmp_handle object,
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
	if (filesystemcmp_rpc(fd, FILESYSTEMCMP_OP_OPEN, &request,
	    sizeof(request), &reply, &length) == -1)
		return (-1);
	memcpy(reply_value, &reply.wire.msg + 1, sizeof(*reply_value));
	return (0);
}

int
filesystemcmp_create(int fd, struct filesystemcmp_handle directory,
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
	if (filesystemcmp_rpc(fd, FILESYSTEMCMP_OP_CREATE, create,
	    sizeof(*create) + name_length, &reply, &length) == -1)
		return (-1);
	memcpy(reply_value, &reply.wire.msg + 1, sizeof(*reply_value));
	return (0);
}

ssize_t
filesystemcmp_pread(int fd, struct filesystemcmp_handle object, void *buffer,
    size_t length, uint64_t offset)
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
	if (filesystemcmp_rpc(fd, FILESYSTEMCMP_OP_READ, &request,
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
filesystemcmp_pwrite(int fd, struct filesystemcmp_handle object,
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
	if (filesystemcmp_rpc(fd, FILESYSTEMCMP_OP_WRITE, io,
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
filesystemcmp_stat(int fd, struct filesystemcmp_handle object,
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
	if (filesystemcmp_rpc(fd, FILESYSTEMCMP_OP_STAT, &request,
	    sizeof(request), &reply, &length) == -1)
		return (-1);
	memcpy(reply_value, &reply.wire.msg + 1, sizeof(*reply_value));
	return (0);
}

int
filesystemcmp_unlink(int fd, struct filesystemcmp_handle directory,
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
	return (filesystemcmp_rpc(fd, FILESYSTEMCMP_OP_UNLINK,
	    unlink_request, sizeof(*unlink_request) + name_length, &reply,
	    &length));
}

int
filesystemcmp_rename(int fd, struct filesystemcmp_handle old_directory,
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
	return (filesystemcmp_rpc(fd, FILESYSTEMCMP_OP_RENAME,
	    rename_request, sizeof(*rename_request) + old_length + new_length,
	    &reply, &length));
}

int
filesystemcmp_close_handle(int fd, struct filesystemcmp_handle object)
{
	union filesystemcmp_buffer reply;
	struct filesystemcmp_close_request request;
	size_t length;

	memset(&request, 0, sizeof(request));
	request.object = object;
	return (filesystemcmp_rpc(fd, FILESYSTEMCMP_OP_CLOSE, &request,
	    sizeof(request), &reply, &length));
}
