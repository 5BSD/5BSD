/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/capsicum.h>
#include <sys/procdesc.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <auditcmp.h>
#include <auditcmp_server.h>
#include <channel.h>
#include <filesystemcmp.h>
#include <filesystemcmp_server.h>
#include <libservice.h>

#include "localfilesystem_probes.h"
#include "store.h"
#ifdef FILESYSTEMCMP_TESTING
#include "filesystemcmp_test.h"
#endif

#define	DEFAULT_MAX_BYTES	(64ULL * 1024 * 1024)
#define	DEFAULT_MAX_OBJECTS	4096
#define	DEFAULT_MAX_FILE_BYTES	(16U * 1024 * 1024)
#define	LOCALFILESYSTEM_NAME	"system.Filesystem"

union wire_buffer {
	max_align_t align;
	struct {
		struct filesystemcmp_msg msg;
		uint8_t payload[FILESYSTEMCMP_MAX_MESSAGE -
		    sizeof(struct filesystemcmp_msg)];
	} wire;
};

static void
audit_policy(struct auditcmp_client *audit, const char *label,
    const char *operation, int error)
{

	if (audit == NULL)
		return;
	if (auditcmp_submit(audit, label, operation, error) == -1)
		syslog(LOG_ERR, "audit %s for %s: %m", operation, label);
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
harden_resource_fd(int fd, bool readonly)
{
	struct stat status;
	cap_rights_t rights;

	if (fstat(fd, &status) == -1)
		return (-1);
	if (!S_ISDIR(status.st_mode)) {
		errno = ENOTDIR;
		return (-1);
	}
	cap_rights_init(&rights, CAP_READ, CAP_PREAD, CAP_SEEK, CAP_FCNTL,
	    CAP_LOOKUP, CAP_FSTAT, CAP_FSTATAT, CAP_FLOCK);
	if (!readonly)
		cap_rights_set(&rights, CAP_WRITE, CAP_PWRITE, CAP_FTRUNCATE,
		    CAP_FSYNC, CAP_CREATE, CAP_MKDIRAT, CAP_UNLINKAT,
		    CAP_RENAMEAT_SOURCE, CAP_RENAMEAT_TARGET);
	return (cap_rights_limit(fd, &rights) == -1 ||
	    cap_fcntls_limit(fd, 0) == -1 ||
	    harden_worker_fd(fd) == -1 ? -1 : 0);
}

static int
send_reply(struct channel_message *request_message,
    const char *label __unused,
    const struct filesystemcmp_msg *request, int error, const void *payload,
    size_t payload_length)
{
	union wire_buffer buffer;
	struct filesystemcmp_msg *reply;
	size_t length;
	int result, saved_errno;

	memset(&buffer, 0, sizeof(buffer));
	reply = &buffer.wire.msg;
	if (filesystemcmp_message_init_reply(reply, request,
	    error == 0 ? 0 : -error) == -1)
		return (-1);
	if (error == 0 && payload_length != 0)
		memcpy(reply + 1, payload, payload_length);
	length = sizeof(*reply) + (error == 0 ? payload_length : 0);
	if (filesystemcmp_validate_message(reply, length,
	    FILESYSTEMCMP_MESSAGE_REPLY) == -1 ||
	    filesystemcmp_validate_fds(reply, 0,
	    FILESYSTEMCMP_MESSAGE_REPLY) == -1)
		result = -1;
	else
		result = channel_send_reply(request_message,
		    &(struct channel_outgoing)
		    CHANNEL_OUTGOING_INITIALIZER(reply, length));
	saved_errno = result == -1 ? errno : 0;
	LOCALFILESYSTEM_PROBE_REQUEST(label, request->opcode,
	    error != 0 ? error : saved_errno);
	errno = saved_errno;
	return (result);
}

static int
request_name(const struct filesystemcmp_msg *message, size_t received,
    size_t fixed, uint32_t length, const void **name)
{

	if (length == 0 || length > FILESYSTEMCMP_NAME_MAX ||
	    received < sizeof(*message) ||
	    fixed + length != received - sizeof(*message)) {
		errno = EPROTO;
		return (-1);
	}
	*name = (const uint8_t *)(message + 1) + fixed;
	return (0);
}

static int
dispatch(struct channel_message *request_message,
    struct filesystem_store *store,
    const struct filesystemcmp_msg *message, size_t received,
    struct auditcmp_client *audit, const char *label)
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
	const struct filesystemcmp_namespace_request *namespace_request;
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
		hello_reply.features = filesystem_store_features(store);
		return (send_reply(request_message, label, message, 0,
		    &hello_reply, sizeof(hello_reply)));
	case FILESYSTEMCMP_OP_OPEN_ROOT:
		if (filesystem_store_root(store, FILESYSTEMCMP_NAMESPACE_SCRATCH,
		    &handle) == -1)
			break;
		handle_reply.handle = handle;
		handle_reply.type = FILESYSTEMCMP_TYPE_DIRECTORY;
		return (send_reply(request_message, label, message, 0,
		    &handle_reply, sizeof(handle_reply)));
	case FILESYSTEMCMP_OP_OPEN_NAMESPACE:
		namespace_request = (const void *)(message + 1);
		if (filesystem_store_root(store, namespace_request->namespace,
		    &handle) == -1)
			break;
		handle_reply.handle = handle;
		handle_reply.type = FILESYSTEMCMP_TYPE_DIRECTORY;
		return (send_reply(request_message, label, message, 0,
		    &handle_reply, sizeof(handle_reply)));
	case FILESYSTEMCMP_OP_LOOKUP:
		lookup = (const void *)(message + 1);
		if (request_name(message, received, sizeof(*lookup),
		    lookup->name_length, &name) == -1 ||
		    filesystem_store_lookup(store, lookup->directory, name,
		    lookup->name_length, &handle) == -1)
			break;
		handle_reply.handle = handle;
		if (filesystem_store_stat(store, handle, &stat_reply) == -1)
			break;
		handle_reply.type = stat_reply.type;
		return (send_reply(request_message, label, message, 0,
		    &handle_reply, sizeof(handle_reply)));
	case FILESYSTEMCMP_OP_CREATE:
		create = (const void *)(message + 1);
		if (request_name(message, received, sizeof(*create),
		    create->name_length, &name) == -1 ||
		    filesystem_store_create_object(store, create->directory, name,
		    create->name_length, create->flags, create->mode,
		    &handle) == -1)
			break;
		handle_reply.handle = handle;
		if (filesystem_store_stat(store, handle, &stat_reply) == -1)
			break;
		handle_reply.type = stat_reply.type;
		audit_policy(audit, label, "create", 0);
		return (send_reply(request_message, label, message, 0,
		    &handle_reply, sizeof(handle_reply)));
	case FILESYSTEMCMP_OP_OPEN:
		open = (const void *)(message + 1);
		if (filesystem_store_open(store, open->object, open->flags) == -1)
			break;
		handle_reply.handle = open->object;
		if (filesystem_store_stat(store, open->object, &stat_reply) == -1)
			break;
		handle_reply.type = stat_reply.type;
		return (send_reply(request_message, label, message, 0,
		    &handle_reply, sizeof(handle_reply)));
	case FILESYSTEMCMP_OP_READ:
		io = (const void *)(message + 1);
		if (io->length > FILESYSTEMCMP_INLINE_MAX) {
			errno = EMSGSIZE;
			break;
		}
		io_reply = (void *)(buffer.wire.payload);
		count = filesystem_store_read(store, io->object, io->offset,
		    io_reply + 1, io->length);
		if (count == -1)
			break;
		memset(io_reply, 0, sizeof(*io_reply));
		io_reply->length = (uint32_t)count;
		return (send_reply(request_message, label, message, 0, io_reply,
		    sizeof(*io_reply) + (size_t)count));
	case FILESYSTEMCMP_OP_WRITE:
		io = (const void *)(message + 1);
		count = filesystem_store_write(store, io->object, io->offset,
		    io + 1, io->length);
		if (count == -1)
			break;
		memset(buffer.wire.payload, 0, sizeof(*io_reply));
		io_reply = (void *)buffer.wire.payload;
		io_reply->length = (uint32_t)count;
		return (send_reply(request_message, label, message, 0, io_reply,
		    sizeof(*io_reply)));
	case FILESYSTEMCMP_OP_STAT:
		close_request = (const void *)(message + 1);
		if (filesystem_store_stat(store, close_request->object,
		    &stat_reply) == -1)
			break;
		return (send_reply(request_message, label, message, 0,
		    &stat_reply, sizeof(stat_reply)));
	case FILESYSTEMCMP_OP_UNLINK:
		unlink = (const void *)(message + 1);
		if (request_name(message, received, sizeof(*unlink),
		    unlink->name_length, &name) == -1 ||
		    filesystem_store_unlink(store, unlink->directory, name,
		    unlink->name_length) == -1)
			break;
		audit_policy(audit, label, "unlink", 0);
		return (send_reply(request_message, label, message, 0, NULL, 0));
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
		if (filesystem_store_rename(store, rename->old_directory, name,
		    rename->old_name_length, rename->new_directory, new_name,
		    rename->new_name_length) == -1)
			break;
		audit_policy(audit, label, "rename", 0);
		return (send_reply(request_message, label, message, 0, NULL, 0));
	case FILESYSTEMCMP_OP_CLOSE:
		close_request = (const void *)(message + 1);
		if (filesystem_store_close(store, close_request->object) == -1)
			break;
		return (send_reply(request_message, label, message, 0, NULL, 0));
	case FILESYSTEMCMP_OP_SYNC:
		close_request = (const void *)(message + 1);
		if (filesystem_store_sync(store, close_request->object) == -1)
			break;
		audit_policy(audit, label, "sync", 0);
		return (send_reply(request_message, label, message, 0, NULL, 0));
	case FILESYSTEMCMP_OP_DUP:
		close_request = (const void *)(message + 1);
		if (filesystem_store_dup(store, close_request->object,
		    &handle) == -1)
			break;
		if (filesystem_store_stat(store, handle, &stat_reply) == -1) {
			error = errno;
			(void)filesystem_store_close(store, handle);
			errno = error;
			break;
		}
		handle_reply.handle = handle;
		handle_reply.type = stat_reply.type;
		return (send_reply(request_message, label, message, 0,
		    &handle_reply, sizeof(handle_reply)));
	}
	error = errno != 0 ? errno : EIO;
	audit_policy(audit, label, "request-denied", error);
	return (send_reply(request_message, label, message, error, NULL, 0));
}

struct worker_state {
	struct filesystem_store	*store;
	struct auditcmp_client	*audit;
	const char		*label;
	int			 terminal_error;
};

static void
handle_request(struct channel *channel __unused,
    struct channel_message *request_message, void *argument)
{
	struct worker_state *state;
	const struct filesystemcmp_msg *message;
	size_t length;

	state = argument;
	message = channel_message_data(request_message);
	length = channel_message_length(request_message);
	if (filesystemcmp_validate_message(message, length,
	    FILESYSTEMCMP_MESSAGE_REQUEST) == -1 ||
	    filesystemcmp_validate_fds(message,
	    channel_message_fd_count(request_message),
	    FILESYSTEMCMP_MESSAGE_REQUEST) == -1) {
		state->terminal_error = EPROTO;
		audit_policy(state->audit, state->label, "malformed-request",
		    EPROTO);
		channel_message_free(request_message);
		return;
	}
	if (dispatch(request_message, state->store, message, length,
	    state->audit, state->label) == -1)
		state->terminal_error = errno;
	channel_message_free(request_message);
}

static int
serve_session(int fd, struct filesystem_store *store,
    struct auditcmp_client *audit, const char *label)
{
	struct channel_options options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
	struct worker_state state;
	struct channel *channel;
	int ready, wants_write;

	if (fd < 0 || store == NULL || label == NULL || label[0] == '\0')
		return (errno = EINVAL, -1);
	memset(&state, 0, sizeof(state));
	channel = NULL;
	state.store = store;
	state.audit = audit;
	state.label = label;
	if (channel_create(fd, &options, &channel) == -1 ||
	    channel_set_request_handler(channel, handle_request, &state) ==
	    -1) {
		if (channel != NULL)
			channel_destroy(channel);
		return (1);
	}
	for (;;) {
		wants_write = channel_wants_write(channel);
		if (wants_write == -1)
			break;
		ready = channel_wait(channel, wants_write, -1);
		if (ready == -1)
			break;
		if ((ready & CHANNEL_WAIT_WRITE) != 0 &&
		    channel_flush(channel) == -1)
			break;
		if ((ready & CHANNEL_WAIT_READ) != 0 &&
		    channel_dispatch(channel) == -1)
			break;
		if (state.terminal_error != 0) {
			errno = state.terminal_error;
			break;
		}
	}
	channel_destroy(channel);
	return (state.terminal_error == 0 ? 0 : 1);
}

#ifdef FILESYSTEMCMP_TESTING
int
filesystemcmp_test_serve(int fd, struct filesystem_store *store,
    const char *label)
{

	return (serve_session(fd, store, NULL, label));
}

int
filesystemcmp_test_harden_resource_fd(int fd, bool readonly)
{

	return (harden_resource_fd(fd, readonly));
}
#endif

#ifndef FILESYSTEMCMP_TESTING
static int
worker(int fd, int barrier, const struct scratch_limits *limits,
    int persistent_fd, int bundle_fd, int audit_fd, const char *label)
{
	struct auditcmp_client *audit;
	struct filesystem_store *store;
	char byte;
	int error, result;

	audit = NULL;
	store = NULL;
	if (auditcmp_client_adopt(audit_fd, &audit) == -1)
		goto fail;
	if (service_worker_protect(SERVICE_PROTECT_EXTERNAL |
	    SERVICE_PROTECT_NOPRIVS | SERVICE_PROTECT_NOFORK |
	    SERVICE_PROTECT_NOIPC | SERVICE_PROTECT_NOFDRECV |
	    SERVICE_PROTECT_NOEXEC | SERVICE_PROTECT_NOSOCK) == -1)
		goto fail;
	service_worker_drop_inherited_authority();
	if (cap_enter() == -1 || filesystem_store_create(limits, persistent_fd,
	    bundle_fd, &store) == -1)
		goto fail;
	close(persistent_fd);
	close(bundle_fd);
	persistent_fd = bundle_fd = -1;
	error = 0;
	if (write(barrier, &error, sizeof(error)) != sizeof(error) ||
	    read(barrier, &byte, 1) != 1) {
		result = 1;
		goto out;
	}
	close(barrier);
	barrier = -1;
	result = serve_session(fd, store, audit, label);
	LOCALFILESYSTEM_PROBE_SESSION_END(label,
	    result == 0 ? 0 : (errno != 0 ? errno : EIO));
out:
	if (barrier >= 0)
		close(barrier);
	if (persistent_fd >= 0)
		close(persistent_fd);
	if (bundle_fd >= 0)
		close(bundle_fd);
	filesystem_store_destroy(store);
	auditcmp_client_close(audit);
	return (result);
fail:
	error = errno;
	(void)write(barrier, &error, sizeof(error));
	result = 1;
	goto out;
}

static int
start_session(int fd, const char *peer_label)
{
	struct service_component_bootstrap *bootstrap;
	struct scratch_limits limits;
	uint64_t instance_id __unused;
	int resources[2] = { -1, -1 };
	int syncfd[2], pd, audit_fd, child_error, error;
	pid_t pid;
	char byte;
	ssize_t n;

	bootstrap = NULL;
	audit_fd = -1;
	if (service_component_accept(fd, &bootstrap) == -1) {
		LOCALFILESYSTEM_PROBE_SESSION(peer_label, 0, errno);
		return (-1);
	}
	instance_id = service_component_instance_id(bootstrap);
	if (service_component_resource_count(bootstrap) != nitems(resources)) {
		error = EPROTO;
		goto reject;
	}
	if (strcmp(service_component_interface(bootstrap),
	    FILESYSTEMCMP_INTERFACE) != 0 ||
	    strcmp(service_component_interface_version(bootstrap),
	    FILESYSTEMCMP_INTERFACE_VERSION) != 0) {
		error = EOPNOTSUPP;
		goto reject;
	}
	resources[0] = service_component_take_resource(bootstrap, 0);
	resources[1] = service_component_take_resource(bootstrap, 1);
	if (resources[0] == -1 || resources[1] == -1) {
		error = errno;
		goto reject;
	}
	if (harden_worker_fd(fd) == -1 ||
	    harden_resource_fd(resources[0], false) == -1 ||
	    harden_resource_fd(resources[1], true) == -1) {
		error = errno;
		goto reject;
	}
	limits.max_bytes = DEFAULT_MAX_BYTES;
	limits.max_objects = DEFAULT_MAX_OBJECTS;
	limits.max_file_bytes = DEFAULT_MAX_FILE_BYTES;
	if (auditcmp_client_prepare(&audit_fd) == -1) {
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
		_exit(worker(fd, syncfd[1], &limits, resources[0], resources[1],
		    audit_fd, peer_label));
	}
	close(audit_fd);
	audit_fd = -1;
	close(resources[0]);
	close(resources[1]);
	resources[0] = resources[1] = -1;
	close(syncfd[1]);
	n = read(syncfd[0], &child_error, sizeof(child_error));
	if (n != sizeof(child_error) || child_error != 0) {
		error = n == sizeof(child_error) ? child_error : EIO;
		(void)pdkill(pd, SIGKILL);
		close(pd);
		close(syncfd[0]);
		goto reject;
	}
	if (service_component_complete(bootstrap,
	    SERVICE_COMPONENT_MEMBER_PROCDESC, pd) == -1) {
		bootstrap = NULL;
		error = errno;
		(void)pdkill(pd, SIGKILL);
		close(pd);
		close(syncfd[0]);
		LOCALFILESYSTEM_PROBE_SESSION(peer_label, instance_id,
		    error);
		errno = error;
		return (-1);
	}
	bootstrap = NULL;
	close(pd);
	byte = 1;
	(void)write(syncfd[0], &byte, 1);
	close(syncfd[0]);
	LOCALFILESYSTEM_PROBE_SESSION(peer_label, instance_id, 0);
	return (0);

reject:
	if (resources[0] >= 0)
		close(resources[0]);
	if (resources[1] >= 0)
		close(resources[1]);
	if (audit_fd >= 0)
		close(audit_fd);
	if (bootstrap != NULL) {
		(void)service_component_fail(bootstrap, error);
		bootstrap = NULL;
	}
	LOCALFILESYSTEM_PROBE_SESSION(peer_label, instance_id, error);
	errno = error;
	return (-1);
}

int
main(void)
{
	struct service_identity identity;
	struct service_listener *listener;
	struct service_provider *provider;
	int error, fd;

	openlog("localfilesystem", LOG_PID | LOG_NDELAY, LOG_DAEMON);
	if (service_provider_create(&provider) == -1 ||
	    service_provider_authorize_capabilities(provider) == -1 ||
	    service_provider_protect(provider, SERVICE_PROTECT_EXTERNAL |
	    SERVICE_PROTECT_NOPRIVS | SERVICE_PROTECT_NOEXEC) == -1 ||
	    service_provider_expose(provider, LOCALFILESYSTEM_NAME,
	    &listener) == -1 ||
	    service_provider_enter_capability_mode(provider) == -1 ||
	    service_provider_ready(provider) == -1) {
		syslog(LOG_ERR, "initialization: %m");
		return (1);
	}
	for (;;) {
		memset(&identity, 0, sizeof(identity));
		identity.size = sizeof(identity);
		if (service_listener_accept(listener, &identity, &fd) == -1) {
			error = errno;
			if (service_provider_quiescing(provider) == 1) {
				if (service_provider_quiesce_complete(provider, 0) == -1)
					syslog(LOG_ERR, "quiesce completion: %m");
				closelog();
				return (0);
			}
			errno = error;
			if (errno == EINTR)
				continue;
			syslog(LOG_ERR, "service_listener_accept: %m");
			return (1);
		}
		if (start_session(fd, identity.client_label) == -1)
			syslog(LOG_WARNING, "session for %s rejected: %m",
			    identity.client_label);
		close(fd);
	}
}
#endif
