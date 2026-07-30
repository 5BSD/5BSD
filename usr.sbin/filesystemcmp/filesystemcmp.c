/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/capsicum.h>
#include <sys/procdesc.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <bsm/audit_kevents.h>
#include <bsm/libbsm.h>
#include <ucl.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <filesystemcmp.h>
#include <libservice.h>

#include "scratch.h"

#define	DEFAULT_MAX_BYTES	(64ULL * 1024 * 1024)
#define	DEFAULT_MAX_OBJECTS	4096
#define	DEFAULT_MAX_FILE_BYTES	(16U * 1024 * 1024)
#define	FILESYSTEMCMP_PROVIDER_NAME	"org.5bsd.FileSystemCmp.scratch"

union wire_buffer {
	max_align_t align;
	struct {
		struct filesystemcmp_msg msg;
		uint8_t payload[FILESYSTEMCMP_MAX_MESSAGE -
		    sizeof(struct filesystemcmp_msg)];
	} wire;
};

static void
audit_policy(const char *label, const char *operation, int error)
{

	(void)audit_submit((short)AUE_FILESYSTEMCMP_POLICY, getuid(),
	    (char)error,
	    error != 0, "client=%s operation=%s result=%d", label, operation,
	    error);
}

/*
 * A session channel and the worker side of the readiness barrier cross
 * exactly one pdfork, then become non-propagating in both processes.
 */
static int
harden_worker_fd(int fd)
{

	return (cap_xfer_limit(fd, CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(fd, CAP_CLOFORK_ONCE) == -1 ||
	    cap_cloexec_limit(fd, CAP_CLOEXEC_LOCKED) == -1 ? -1 : 0);
}

static int
parse_limit(const ucl_object_t *root, const char *name, uint64_t maximum,
    uint64_t *value)
{
	const ucl_object_t *object;
	int64_t parsed;

	object = ucl_object_lookup(root, name);
	if (object == NULL)
		return (0);
	if (!ucl_object_toint_safe(object, &parsed) || parsed <= 0 ||
	    (uint64_t)parsed > maximum) {
		errno = EINVAL;
		return (-1);
	}
	*value = (uint64_t)parsed;
	return (0);
}

static int
parse_options(const char *json, struct scratch_limits *limits)
{
	static const char *const names[] = {
	    "max_bytes", "max_objects", "max_file_bytes"
	};
	struct ucl_parser *parser;
	ucl_object_t *root;
	const ucl_object_t *current;
	ucl_object_iter_t iterator;
	const char *key;
	uint64_t value;
	size_t i;
	int error;

	limits->max_bytes = DEFAULT_MAX_BYTES;
	limits->max_objects = DEFAULT_MAX_OBJECTS;
	limits->max_file_bytes = DEFAULT_MAX_FILE_BYTES;
	parser = ucl_parser_new(UCL_PARSER_NO_FILEVARS |
	    UCL_PARSER_NO_IMPLICIT_ARRAYS);
	if (parser == NULL)
		return (-1);
	if (!ucl_parser_add_string(parser, json, 0)) {
		errno = EINVAL;
		ucl_parser_free(parser);
		return (-1);
	}
	root = ucl_parser_get_object(parser);
	if (root == NULL || ucl_object_type(root) != UCL_OBJECT) {
		errno = EINVAL;
		goto fail;
	}
	iterator = NULL;
	while ((current = ucl_object_iterate(root, &iterator, true)) != NULL) {
		key = ucl_object_key(current);
		for (i = 0; i < nitems(names); i++)
			if (strcmp(key, names[i]) == 0)
				break;
		if (i == nitems(names)) {
			errno = EINVAL;
			goto fail;
		}
	}
	value = limits->max_bytes;
	if (parse_limit(root, "max_bytes", UINT64_MAX, &value) == -1)
		goto fail;
	limits->max_bytes = value;
	value = limits->max_objects;
	if (parse_limit(root, "max_objects", 1048576, &value) == -1)
		goto fail;
	limits->max_objects = (uint32_t)value;
	value = limits->max_file_bytes;
	if (parse_limit(root, "max_file_bytes", UINT32_MAX, &value) == -1)
		goto fail;
	limits->max_file_bytes = (uint32_t)value;
	if (limits->max_file_bytes > limits->max_bytes) {
		errno = EINVAL;
		goto fail;
	}
	ucl_object_unref(root);
	ucl_parser_free(parser);
	return (0);

fail:
	error = errno;
	if (root != NULL)
		ucl_object_unref(root);
	ucl_parser_free(parser);
	errno = error;
	return (-1);
}

static int
send_reply(int fd, const struct filesystemcmp_msg *request, int error,
    const void *payload, size_t payload_length)
{
	union wire_buffer buffer;
	struct filesystemcmp_msg *reply;

	memset(&buffer, 0, sizeof(buffer));
	reply = &buffer.wire.msg;
	reply->magic = FILESYSTEMCMP_MAGIC;
	reply->version = FILESYSTEMCMP_ABI_VERSION;
	reply->opcode = request->opcode;
	reply->flags = FILESYSTEMCMP_MSG_F_REPLY;
	reply->length = sizeof(*reply) + (error == 0 ? payload_length : 0);
	reply->request_id = request->request_id;
	reply->status = error == 0 ? 0 : -error;
	if (error == 0 && payload_length != 0)
		memcpy(reply + 1, payload, payload_length);
	return (filesystemcmp_send_message(fd, reply, reply->length, NULL, 0));
}

static int
request_name(const struct filesystemcmp_msg *message, size_t fixed,
    uint32_t length, const void **name)
{

	if (length == 0 || length > FILESYSTEMCMP_NAME_MAX ||
	    fixed + length != message->length - sizeof(*message)) {
		errno = EPROTO;
		return (-1);
	}
	*name = (const uint8_t *)(message + 1) + fixed;
	return (0);
}

static int
dispatch(int fd, struct scratch_store *store,
    const struct filesystemcmp_msg *message, const char *label)
{
	struct filesystemcmp_handle_reply handle_reply;
	struct filesystemcmp_hello_reply hello_reply;
	struct filesystemcmp_io_reply *io_reply;
	struct filesystemcmp_stat_reply stat_reply;
	const struct filesystemcmp_lookup_request *lookup;
	const struct filesystemcmp_create_request *create;
	const struct filesystemcmp_io_request *io;
	const struct filesystemcmp_unlink_request *unlink;
	const struct filesystemcmp_rename_request *rename;
	const struct filesystemcmp_open_request *open;
	const struct filesystemcmp_close_request *close_request;
	union wire_buffer buffer;
	struct filesystemcmp_handle handle;
	const void *name, *new_name;
	ssize_t count;
	int error;

	error = 0;
	memset(&handle_reply, 0, sizeof(handle_reply));
	switch (message->opcode) {
	case FILESYSTEMCMP_OP_HELLO:
		memset(&hello_reply, 0, sizeof(hello_reply));
		hello_reply.version = FILESYSTEMCMP_ABI_VERSION;
		hello_reply.features = FILESYSTEMCMP_FEATURE_INLINE_IO;
		return (send_reply(fd, message, 0, &hello_reply,
		    sizeof(hello_reply)));
	case FILESYSTEMCMP_OP_OPEN_ROOT:
		if (scratch_root(store, &handle) == -1)
			break;
		handle_reply.handle = handle;
		handle_reply.type = FILESYSTEMCMP_TYPE_DIRECTORY;
		return (send_reply(fd, message, 0, &handle_reply,
		    sizeof(handle_reply)));
	case FILESYSTEMCMP_OP_LOOKUP:
		lookup = (const void *)(message + 1);
		if (request_name(message, sizeof(*lookup), lookup->name_length,
		    &name) == -1 ||
		    scratch_lookup(store, lookup->directory, name,
		    lookup->name_length, &handle) == -1)
			break;
		handle_reply.handle = handle;
		if (scratch_stat(store, handle, &stat_reply) == -1)
			break;
		handle_reply.type = stat_reply.type;
		return (send_reply(fd, message, 0, &handle_reply,
		    sizeof(handle_reply)));
	case FILESYSTEMCMP_OP_CREATE:
		create = (const void *)(message + 1);
		if (request_name(message, sizeof(*create), create->name_length,
		    &name) == -1 ||
		    scratch_create(store, create->directory, name,
		    create->name_length, create->flags, create->mode,
		    &handle) == -1)
			break;
		handle_reply.handle = handle;
		if (scratch_stat(store, handle, &stat_reply) == -1)
			break;
		handle_reply.type = stat_reply.type;
		audit_policy(label, "create", 0);
		return (send_reply(fd, message, 0, &handle_reply,
		    sizeof(handle_reply)));
	case FILESYSTEMCMP_OP_OPEN:
		open = (const void *)(message + 1);
		if (scratch_open(store, open->object, open->flags) == -1)
			break;
		handle_reply.handle = open->object;
		if (scratch_stat(store, open->object, &stat_reply) == -1)
			break;
		handle_reply.type = stat_reply.type;
		return (send_reply(fd, message, 0, &handle_reply,
		    sizeof(handle_reply)));
	case FILESYSTEMCMP_OP_READ:
		io = (const void *)(message + 1);
		if (io->length > FILESYSTEMCMP_INLINE_MAX) {
			errno = EMSGSIZE;
			break;
		}
		io_reply = (void *)(buffer.wire.payload);
		count = scratch_read(store, io->object, io->offset, io_reply + 1,
		    io->length);
		if (count == -1)
			break;
		memset(io_reply, 0, sizeof(*io_reply));
		io_reply->length = (uint32_t)count;
		return (send_reply(fd, message, 0, io_reply,
		    sizeof(*io_reply) + (size_t)count));
	case FILESYSTEMCMP_OP_WRITE:
		io = (const void *)(message + 1);
		count = scratch_write(store, io->object, io->offset, io + 1,
		    io->length);
		if (count == -1)
			break;
		memset(buffer.wire.payload, 0, sizeof(*io_reply));
		io_reply = (void *)buffer.wire.payload;
		io_reply->length = (uint32_t)count;
		return (send_reply(fd, message, 0, io_reply,
		    sizeof(*io_reply)));
	case FILESYSTEMCMP_OP_STAT:
		close_request = (const void *)(message + 1);
		if (scratch_stat(store, close_request->object, &stat_reply) == -1)
			break;
		return (send_reply(fd, message, 0, &stat_reply,
		    sizeof(stat_reply)));
	case FILESYSTEMCMP_OP_UNLINK:
		unlink = (const void *)(message + 1);
		if (request_name(message, sizeof(*unlink), unlink->name_length,
		    &name) == -1 ||
		    scratch_unlink(store, unlink->directory, name,
		    unlink->name_length) == -1)
			break;
		audit_policy(label, "unlink", 0);
		return (send_reply(fd, message, 0, NULL, 0));
	case FILESYSTEMCMP_OP_RENAME:
		rename = (const void *)(message + 1);
		if (rename->old_name_length == 0 ||
		    rename->new_name_length == 0 ||
		    rename->old_name_length > FILESYSTEMCMP_NAME_MAX ||
		    rename->new_name_length > FILESYSTEMCMP_NAME_MAX) {
			errno = EINVAL;
			break;
		}
		name = rename + 1;
		new_name = (const uint8_t *)name + rename->old_name_length;
		if (scratch_rename(store, rename->old_directory, name,
		    rename->old_name_length, rename->new_directory, new_name,
		    rename->new_name_length) == -1)
			break;
		audit_policy(label, "rename", 0);
		return (send_reply(fd, message, 0, NULL, 0));
	case FILESYSTEMCMP_OP_CLOSE:
	case FILESYSTEMCMP_OP_NOTIFY:
		return (send_reply(fd, message, 0, NULL, 0));
	case FILESYSTEMCMP_OP_ATTACH_RINGS:
		errno = EOPNOTSUPP;
		break;
	}
	error = errno != 0 ? errno : EIO;
	audit_policy(label, "request-denied", error);
	return (send_reply(fd, message, error, NULL, 0));
}

static int
worker(int fd, int barrier, const struct scratch_limits *limits,
    const char *label)
{
	union wire_buffer buffer;
	struct scratch_store *store;
	size_t nfds, i;
	ssize_t received;
	char byte;
	int fds[8], error;

	if (service_protect(SERVICE_PROTECT_EXTERNAL |
	    SERVICE_PROTECT_NOPRIVS | SERVICE_PROTECT_NOFORK |
	    SERVICE_PROTECT_NOIPC | SERVICE_PROTECT_NOEXEC |
	    SERVICE_PROTECT_NOSOCK) == -1) {
		error = errno;
		(void)write(barrier, &error, sizeof(error));
		return (1);
	}
	service_drop_inherited_authority();
	if (cap_enter() == -1) {
		error = errno;
		(void)write(barrier, &error, sizeof(error));
		return (1);
	}
	if (scratch_store_create(limits, &store) == -1) {
		error = errno;
		(void)write(barrier, &error, sizeof(error));
		return (1);
	}
	error = 0;
	if (write(barrier, &error, sizeof(error)) != sizeof(error) ||
	    read(barrier, &byte, 1) != 1) {
		scratch_store_destroy(store);
		return (1);
	}
	close(barrier);
	for (;;) {
		nfds = nitems(fds);
		received = filesystemcmp_receive_message(fd, &buffer,
		    sizeof(buffer), fds, &nfds);
		if (received == -1) {
			if (errno == ECONNRESET || errno == EPIPE)
				break;
			audit_policy(label, "malformed-request", errno);
			break;
		}
		for (i = 0; i < nfds; i++)
			close(fds[i]);
		if (dispatch(fd, store, &buffer.wire.msg, label) == -1)
			break;
	}
	scratch_store_destroy(store);
	close(fd);
	return (0);
}

static int
start_session(int fd, const char *peer_label)
{
	struct component_session_bootstrap bootstrap;
	struct scratch_limits limits;
	char options[COMPONENT_SESSION_OPTIONS_MAX];
	int syncfd[2], pd, child_error, error;
	pid_t pid;
	char byte;
	ssize_t n;

	if (service_component_recv_bootstrap(fd, &bootstrap, options,
	    sizeof(options)) == -1)
		return (-1);
	if (strcmp(bootstrap.interface, FILESYSTEMCMP_INTERFACE) != 0 ||
	    strcmp(bootstrap.interface_version,
	    FILESYSTEMCMP_INTERFACE_VERSION) != 0 ||
	    bootstrap.scope != COMPONENT_SESSION_SCOPE_PRIVATE) {
		error = EOPNOTSUPP;
		goto reject;
	}
	if (harden_worker_fd(fd) == -1) {
		error = errno;
		goto reject;
	}
	if (parse_options(options, &limits) == -1) {
		error = errno;
		goto reject;
	}
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, syncfd) == -1) {
		error = errno;
		goto reject;
	}
	if (cap_xfer_limit(syncfd[0], CAP_XFER_NONE) == -1 ||
	    cap_clofork_limit(syncfd[0], CAP_CLOFORK_LOCKED) == -1 ||
	    cap_cloexec_limit(syncfd[0], CAP_CLOEXEC_LOCKED) == -1 ||
	    harden_worker_fd(syncfd[1]) == -1) {
		error = errno;
		close(syncfd[0]);
		close(syncfd[1]);
		goto reject;
	}
	pid = pdfork(&pd, PD_CLOEXEC | PD_DAEMON);
	if (pid == -1) {
		error = errno;
		close(syncfd[0]);
		close(syncfd[1]);
		goto reject;
	}
	if (pid == 0) {
		close(syncfd[0]);
		_exit(worker(fd, syncfd[1], &limits, peer_label));
	}
	close(syncfd[1]);
	n = read(syncfd[0], &child_error, sizeof(child_error));
	if (n != sizeof(child_error) || child_error != 0) {
		error = n == sizeof(child_error) ? child_error : EIO;
		(void)pdkill(pd, SIGKILL);
		close(pd);
		close(syncfd[0]);
		goto reject;
	}
	if (service_component_send_reply(fd, bootstrap.instance_id, 0,
	    COMPONENT_SESSION_MEMBER_PROCDESC, pd) == -1) {
		error = errno;
		(void)pdkill(pd, SIGKILL);
		close(pd);
		close(syncfd[0]);
		audit_policy(peer_label, "session-bootstrap", error);
		errno = error;
		return (-1);
	}
	close(pd);
	byte = 1;
	(void)write(syncfd[0], &byte, 1);
	close(syncfd[0]);
	audit_policy(peer_label, "session-bootstrap", 0);
	return (0);

reject:
	(void)service_component_send_reply(fd, bootstrap.instance_id, error, 0,
	    -1);
	audit_policy(peer_label, "session-bootstrap", error);
	errno = error;
	return (-1);
}

int
main(void)
{
	char label[COMPONENT_SESSION_LABEL_MAX];
	int fd;

	openlog("filesystemcmp", LOG_PID | LOG_NDELAY, LOG_DAEMON);
	if (service_init() == -1 ||
	    service_authorize_capabilities() == -1 ||
	    service_protect(SERVICE_PROTECT_EXTERNAL |
	    SERVICE_PROTECT_NOPRIVS | SERVICE_PROTECT_NOEXEC) == -1 ||
	    service_register(FILESYSTEMCMP_PROVIDER_NAME) == -1 ||
	    service_ready() == -1) {
		syslog(LOG_ERR, "initialization: %m");
		return (1);
	}
	for (;;) {
		fd = service_accept(label, sizeof(label));
		if (fd == -1) {
			if (errno == EINTR)
				continue;
			syslog(LOG_ERR, "service_accept: %m");
			return (1);
		}
		if (start_session(fd, label) == -1)
			syslog(LOG_WARNING, "session for %s rejected: %m", label);
		close(fd);
	}
}
