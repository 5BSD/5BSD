/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/ioctl.h>
#include <sys/capsicum.h>
#include <sys/param.h>
#include <sys/wait.h>

#include <dev/mac_capability/mac_capability_channel_proto.h>
#include <dev/mac_capability/mac_capability_ioctl.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <filesystemcmp.h>
#include <filesystemcmp_server.h>
#include <libservice.h>

#include "filesystemcmp_test.h"
#include "store.h"

union wire_buffer {
	max_align_t align;
	uint8_t bytes[FILESYSTEMCMP_MAX_MESSAGE];
};

struct fixture {
	struct service_session *session;
	pid_t child;
};

static int
capability_connect(const char *name)
{
	struct mac_capability_connect_args connect;
	int control, error;

	control = open("/dev/mac_capability", O_RDWR | O_CLOEXEC);
	ATF_REQUIRE_MSG(control >= 0, "open mac_capability: %s",
	    strerror(errno));
	memset(&connect, 0, sizeof(connect));
	strlcpy(connect.name, name, sizeof(connect.name));
	if (ioctl(control, MAC_CAPABILITY_CONNECT, &connect) == -1) {
		error = errno;
		close(control);
		errno = error;
		return (-1);
	}
	close(control);
	return (connect.fd);
}

static void
channel_pair(int *client, int *provider)
{
	struct mac_capability_recvmsg_args receive;
	struct mac_capability_sendmsg_args send;
	uint32_t operation;

	*client = capability_connect("channel");
	ATF_REQUIRE(*client >= 0);
	operation = CHANNEL_OP_CREATE;
	memset(&send, 0, sizeof(send));
	send.payload = &operation;
	send.payload_len = sizeof(operation);
	ATF_REQUIRE_EQ(0, ioctl(*client, MAC_CAPABILITY_SENDMSG, &send));
	memset(&receive, 0, sizeof(receive));
	receive.fds = provider;
	receive.nfds = 1;
	ATF_REQUIRE_EQ(0, ioctl(*client, MAC_CAPABILITY_RECVMSG, &receive));
	ATF_REQUIRE_EQ(1, receive.nfds);
}

static void
fixture_create(struct fixture *fixture)
{
	struct scratch_limits limits = {
		.max_bytes = 4096,
		.max_objects = 16,
		.max_file_bytes = 1024,
	};
	struct filesystem_store *store;
	int client, provider;

	memset(fixture, 0, sizeof(*fixture));
	channel_pair(&client, &provider);
	fixture->child = fork();
	ATF_REQUIRE(fixture->child >= 0);
	if (fixture->child == 0) {
		close(client);
		if (filesystem_store_create(&limits, -1, -1, &store) == -1)
			_exit(100);
		int result = filesystemcmp_test_serve(provider, store,
		    "org.test.filesystem");
		filesystem_store_destroy(store);
		_exit(result);
	}
	close(provider);
	ATF_REQUIRE_EQ(0, service_session_create(client, &fixture->session));
}

static void
fixture_destroy(struct fixture *fixture, int expected_status)
{
	int status;

	service_session_close(fixture->session);
	ATF_REQUIRE_EQ(fixture->child, waitpid(fixture->child, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	ATF_CHECK_EQ(expected_status, WEXITSTATUS(status));
}

static int
call(struct fixture *fixture, const void *request, size_t request_length,
    const int *fds, size_t nfds, union wire_buffer *reply, size_t *reply_length)
{
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message message = {
		.size = sizeof(message),
		.data = request,
		.length = request_length,
		.fds = fds,
		.nfds = nfds,
	};
	struct service_reply response = {
		.size = sizeof(response),
		.data = reply->bytes,
		.capacity = sizeof(reply->bytes),
	};

	if (service_session_call(fixture->session, &message, &response,
	    &options) == -1)
		return (-1);
	*reply_length = response.length;
	return (0);
}

static int
reply_status(union wire_buffer *wire, size_t length, uint16_t opcode)
{
	struct filesystemcmp_msg *message = (void *)wire->bytes;

	ATF_REQUIRE_EQ(0, filesystemcmp_validate_message(message, length,
	    FILESYSTEMCMP_MESSAGE_REPLY));
	ATF_REQUIRE_EQ(opcode, message->opcode);
	return (-message->status);
}

static int
request_status(struct fixture *fixture, uint16_t opcode, const void *payload,
    size_t payload_length, const int *fds, size_t nfds)
{
	union wire_buffer request, reply;
	struct filesystemcmp_msg *message;
	size_t length;

	ATF_REQUIRE(payload_length <= sizeof(request.bytes) - sizeof(*message));
	memset(&request, 0, sizeof(request));
	message = (void *)request.bytes;
	ATF_REQUIRE_EQ(0, filesystemcmp_message_init(message, opcode, 0));
	if (payload_length != 0)
		memcpy(message + 1, payload, payload_length);
	ATF_REQUIRE_EQ(0, call(fixture, message,
	    sizeof(*message) + payload_length, fds, nfds, &reply, &length));
	return (reply_status(&reply, length, opcode));
}

ATF_TC(provider_object_lifecycle);
ATF_TC_HEAD(provider_object_lifecycle, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "The real provider dispatcher performs a complete scratch object lifecycle");
}
ATF_TC_BODY(provider_object_lifecycle, tc)
{
	struct fixture fixture;
	union wire_buffer request, reply;
	struct filesystemcmp_msg *message;
	struct filesystemcmp_handle root, file, duplicate;
	struct filesystemcmp_handle_reply *handle_reply;
	struct filesystemcmp_hello hello;
	struct filesystemcmp_create_request *create;
	struct filesystemcmp_io_request *io;
	struct filesystemcmp_io_reply *io_reply;
	struct filesystemcmp_close_request *close_request;
	struct filesystemcmp_namespace_request namespace_request;
	struct filesystemcmp_open_request open_request;
	struct filesystemcmp_lookup_request *lookup_request;
	struct filesystemcmp_rename_request *rename_request;
	struct filesystemcmp_unlink_request *unlink_request;
	size_t length;

	fixture_create(&fixture);
	hello = (struct filesystemcmp_hello){
	    .min_version = FILESYSTEMCMP_ABI_VERSION,
	    .max_version = FILESYSTEMCMP_ABI_VERSION,
	};
	ATF_CHECK_EQ(0, request_status(&fixture, FILESYSTEMCMP_OP_HELLO,
	    &hello, sizeof(hello), NULL, 0));
	message = (void *)request.bytes;
	ATF_REQUIRE_EQ(0, filesystemcmp_message_init(message,
	    FILESYSTEMCMP_OP_OPEN_ROOT, 0));
	ATF_REQUIRE_EQ(0, call(&fixture, message, sizeof(*message), NULL, 0,
	    &reply, &length));
	ATF_REQUIRE_EQ(0, reply_status(&reply, length,
	    FILESYSTEMCMP_OP_OPEN_ROOT));
	handle_reply = (void *)(reply.bytes + sizeof(*message));
	root = handle_reply->handle;
	namespace_request = (struct filesystemcmp_namespace_request){
	    .namespace = FILESYSTEMCMP_NAMESPACE_SCRATCH,
	};
	ATF_CHECK_EQ(0, request_status(&fixture,
	    FILESYSTEMCMP_OP_OPEN_NAMESPACE, &namespace_request,
	    sizeof(namespace_request), NULL, 0));

	memset(&request, 0, sizeof(request));
	message = (void *)request.bytes;
	ATF_REQUIRE_EQ(0, filesystemcmp_message_init(message,
	    FILESYSTEMCMP_OP_CREATE, 0));
	create = (void *)(message + 1);
	create->directory = root;
	create->name_length = 4;
	create->flags = FILESYSTEMCMP_CREATE_EXCLUSIVE;
	create->mode = 0600;
	memcpy(create + 1, "data", 4);
	ATF_REQUIRE_EQ(0, call(&fixture, message,
	    sizeof(*message) + sizeof(*create) + 4, NULL, 0, &reply, &length));
	ATF_REQUIRE_EQ(0, reply_status(&reply, length, FILESYSTEMCMP_OP_CREATE));
	handle_reply = (void *)(reply.bytes + sizeof(*message));
	file = handle_reply->handle;

	memset(&request, 0, sizeof(request));
	message = (void *)request.bytes;
	ATF_REQUIRE_EQ(0, filesystemcmp_message_init(message,
	    FILESYSTEMCMP_OP_LOOKUP, 0));
	lookup_request = (void *)(message + 1);
	lookup_request->directory = root;
	lookup_request->name_length = 4;
	memcpy(lookup_request + 1, "data", 4);
	ATF_REQUIRE_EQ(0, call(&fixture, message,
	    sizeof(*message) + sizeof(*lookup_request) + 4, NULL, 0, &reply,
	    &length));
	ATF_REQUIRE_EQ(0, reply_status(&reply, length,
	    FILESYSTEMCMP_OP_LOOKUP));
	handle_reply = (void *)(reply.bytes + sizeof(*message));
	ATF_CHECK_EQ(file.object, handle_reply->handle.object);
	ATF_CHECK_EQ(file.generation, handle_reply->handle.generation);

	open_request = (struct filesystemcmp_open_request){
	    .object = file,
	    .flags = FILESYSTEMCMP_OPEN_READ | FILESYSTEMCMP_OPEN_WRITE,
	};
	ATF_CHECK_EQ(0, request_status(&fixture, FILESYSTEMCMP_OP_OPEN,
	    &open_request, sizeof(open_request), NULL, 0));

	memset(&request, 0, sizeof(request));
	message = (void *)request.bytes;
	ATF_REQUIRE_EQ(0, filesystemcmp_message_init(message,
	    FILESYSTEMCMP_OP_WRITE, 0));
	io = (void *)(message + 1);
	io->object = file;
	io->length = 5;
	memcpy(io + 1, "hello", 5);
	ATF_REQUIRE_EQ(0, call(&fixture, message,
	    sizeof(*message) + sizeof(*io) + 5, NULL, 0, &reply, &length));
	ATF_REQUIRE_EQ(0, reply_status(&reply, length, FILESYSTEMCMP_OP_WRITE));

	memset(&request, 0, sizeof(request));
	message = (void *)request.bytes;
	ATF_REQUIRE_EQ(0, filesystemcmp_message_init(message,
	    FILESYSTEMCMP_OP_READ, 0));
	io = (void *)(message + 1);
	io->object = file;
	io->length = 5;
	ATF_REQUIRE_EQ(0, call(&fixture, message,
	    sizeof(*message) + sizeof(*io), NULL, 0, &reply, &length));
	ATF_REQUIRE_EQ(0, reply_status(&reply, length, FILESYSTEMCMP_OP_READ));
	io_reply = (void *)(reply.bytes + sizeof(*message));
	ATF_CHECK_EQ(5, io_reply->length);
	ATF_CHECK_EQ(0, memcmp(io_reply + 1, "hello", 5));

	ATF_CHECK_EQ(0, request_status(&fixture, FILESYSTEMCMP_OP_STAT,
	    &(struct filesystemcmp_close_request){ .object = file },
	    sizeof(struct filesystemcmp_close_request), NULL, 0));
	ATF_CHECK_EQ(0, request_status(&fixture, FILESYSTEMCMP_OP_SYNC,
	    &(struct filesystemcmp_close_request){ .object = file },
	    sizeof(struct filesystemcmp_close_request), NULL, 0));

	memset(&request, 0, sizeof(request));
	message = (void *)request.bytes;
	ATF_REQUIRE_EQ(0, filesystemcmp_message_init(message,
	    FILESYSTEMCMP_OP_DUP, 0));
	close_request = (void *)(message + 1);
	close_request->object = file;
	ATF_REQUIRE_EQ(0, call(&fixture, message,
	    sizeof(*message) + sizeof(*close_request), NULL, 0, &reply, &length));
	ATF_REQUIRE_EQ(0, reply_status(&reply, length, FILESYSTEMCMP_OP_DUP));
	handle_reply = (void *)(reply.bytes + sizeof(*message));
	duplicate = handle_reply->handle;
	/* Scratch handles are immutable opaque values and need no fd duplicate. */
	ATF_CHECK_EQ(file.object, duplicate.object);
	ATF_CHECK_EQ(file.generation, duplicate.generation);

	close_request->object = file;
	ATF_REQUIRE_EQ(0, filesystemcmp_message_init(message,
	    FILESYSTEMCMP_OP_CLOSE, 0));
	ATF_REQUIRE_EQ(0, call(&fixture, message,
	    sizeof(*message) + sizeof(*close_request), NULL, 0, &reply, &length));
	ATF_CHECK_EQ(0, reply_status(&reply, length, FILESYSTEMCMP_OP_CLOSE));
	close_request->object = duplicate;
	ATF_REQUIRE_EQ(0, call(&fixture, message,
	    sizeof(*message) + sizeof(*close_request), NULL, 0, &reply, &length));
	ATF_CHECK_EQ(0, reply_status(&reply, length, FILESYSTEMCMP_OP_CLOSE));

	memset(&request, 0, sizeof(request));
	message = (void *)request.bytes;
	ATF_REQUIRE_EQ(0, filesystemcmp_message_init(message,
	    FILESYSTEMCMP_OP_RENAME, 0));
	rename_request = (void *)(message + 1);
	rename_request->old_directory = root;
	rename_request->new_directory = root;
	rename_request->old_name_length = 4;
	rename_request->new_name_length = 7;
	memcpy(rename_request + 1, "datarenamed", 11);
	ATF_REQUIRE_EQ(0, call(&fixture, message,
	    sizeof(*message) + sizeof(*rename_request) + 11, NULL, 0, &reply,
	    &length));
	ATF_CHECK_EQ(0, reply_status(&reply, length, FILESYSTEMCMP_OP_RENAME));

	memset(&request, 0, sizeof(request));
	message = (void *)request.bytes;
	ATF_REQUIRE_EQ(0, filesystemcmp_message_init(message,
	    FILESYSTEMCMP_OP_UNLINK, 0));
	unlink_request = (void *)(message + 1);
	unlink_request->directory = root;
	unlink_request->name_length = 7;
	memcpy(unlink_request + 1, "renamed", 7);
	ATF_REQUIRE_EQ(0, call(&fixture, message,
	    sizeof(*message) + sizeof(*unlink_request) + 7, NULL, 0, &reply,
	    &length));
	ATF_CHECK_EQ(0, reply_status(&reply, length, FILESYSTEMCMP_OP_UNLINK));
	fixture_destroy(&fixture, 0);
}

ATF_TC(provider_errors_and_malformed_channel);
ATF_TC_HEAD(provider_errors_and_malformed_channel, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr",
	    "Provider errors are correlated and malformed descriptor-bearing requests terminate the session");
}
ATF_TC_BODY(provider_errors_and_malformed_channel, tc)
{
	struct fixture fixture;
	union wire_buffer request, reply;
	struct filesystemcmp_msg *message = (void *)request.bytes;
	struct filesystemcmp_hello *hello;
	struct filesystemcmp_namespace_request *namespace_request;
	size_t length;
	int pipefd[2];

	fixture_create(&fixture);
	memset(&request, 0, sizeof(request));
	ATF_REQUIRE_EQ(0, filesystemcmp_message_init(message,
	    FILESYSTEMCMP_OP_OPEN_NAMESPACE, 0));
	namespace_request = (void *)(message + 1);
	namespace_request->namespace = FILESYSTEMCMP_NAMESPACE_PERSISTENT;
	ATF_REQUIRE_EQ(0, call(&fixture, message,
	    sizeof(*message) + sizeof(*namespace_request), NULL, 0, &reply,
	    &length));
	ATF_CHECK_EQ(ENOENT, reply_status(&reply, length,
	    FILESYSTEMCMP_OP_OPEN_NAMESPACE));

	ATF_REQUIRE_EQ(0, pipe(pipefd));
	ATF_REQUIRE_EQ(0, filesystemcmp_message_init(message,
	    FILESYSTEMCMP_OP_HELLO, 0));
	hello = (void *)(message + 1);
	hello->min_version = FILESYSTEMCMP_ABI_VERSION;
	hello->max_version = FILESYSTEMCMP_ABI_VERSION;
	ATF_CHECK_EQ(-1, call(&fixture, message,
	    sizeof(*message) + sizeof(*hello), &pipefd[0], 1, &reply, &length));
	close(pipefd[0]);
	close(pipefd[1]);
	fixture_destroy(&fixture, 1);
}

ATF_TC_WITHOUT_HEAD(arguments);
ATF_TC_BODY(arguments, tc)
{
	struct scratch_limits limits = {
		.max_bytes = 1, .max_objects = 1, .max_file_bytes = 1,
	};
	struct filesystem_store *store;

	ATF_REQUIRE_EQ(0, filesystem_store_create(&limits, -1, -1, &store));
	ATF_CHECK_ERRNO(EINVAL,
	    filesystemcmp_test_serve(-1, store, "org.test") == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    filesystemcmp_test_serve(0, NULL, "org.test") == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    filesystemcmp_test_serve(0, store, "") == -1);
	filesystem_store_destroy(store);
}

ATF_TC_WITHOUT_HEAD(resource_fd_type_validation);
ATF_TC_BODY(resource_fd_type_validation, tc)
{
	char path[] = "resource-file.XXXXXX";
	int fd;

	fd = mkstemp(path);
	ATF_REQUIRE(fd >= 0);
	errno = 0;
	ATF_REQUIRE_ERRNO(ENOTDIR,
	    filesystemcmp_test_harden_resource_fd(fd, true) == -1);
	ATF_REQUIRE_EQ(0, close(fd));
	ATF_REQUIRE_EQ(0, unlink(path));
}

/*
 * A hardened resource directory grants read-mmap so consumers can mmap
 * broker-supplied files; write-mmap follows the writable/read-only split, and
 * executable mappings are never granted.
 */
ATF_TC_WITHOUT_HEAD(resource_fd_grants_mmap);
ATF_TC_BODY(resource_fd_grants_mmap, tc)
{
	char tmpl[] = "resdir.XXXXXX";
	char *dir;
	cap_rights_t rights, want;
	int fd;

	dir = mkdtemp(tmpl);
	ATF_REQUIRE(dir != NULL);

	/* Read-only root: read-mmap granted, write-mmap and exec-mmap withheld. */
	fd = open(dir, O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, filesystemcmp_test_harden_resource_fd(fd, true));
	ATF_REQUIRE_EQ(0, cap_rights_get(fd, &rights));
	cap_rights_init(&want, CAP_MMAP_R);
	ATF_CHECK(cap_rights_contains(&rights, &want));
	cap_rights_init(&want, CAP_MMAP_W);
	ATF_CHECK(!cap_rights_contains(&rights, &want));
	cap_rights_init(&want, CAP_MMAP_X);
	ATF_CHECK(!cap_rights_contains(&rights, &want));
	ATF_REQUIRE_EQ(0, close(fd));

	/* Writable root: read- and write-mmap granted, exec-mmap still withheld. */
	fd = open(dir, O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, filesystemcmp_test_harden_resource_fd(fd, false));
	ATF_REQUIRE_EQ(0, cap_rights_get(fd, &rights));
	cap_rights_init(&want, CAP_MMAP_R, CAP_MMAP_W);
	ATF_CHECK(cap_rights_contains(&rights, &want));
	cap_rights_init(&want, CAP_MMAP_X);
	ATF_CHECK(!cap_rights_contains(&rights, &want));
	ATF_REQUIRE_EQ(0, close(fd));

	ATF_REQUIRE_EQ(0, rmdir(dir));
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, provider_object_lifecycle);
	ATF_TP_ADD_TC(tp, provider_errors_and_malformed_channel);
	ATF_TP_ADD_TC(tp, arguments);
	ATF_TP_ADD_TC(tp, resource_fd_type_validation);
	ATF_TP_ADD_TC(tp, resource_fd_grants_mmap);
	return (atf_no_error());
}
