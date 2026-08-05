/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/capsicum.h>
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

#include <kldmgr.h>
#include <kldmgr_server.h>
#include <libservice.h>

#include "kldmgrd_ops.h"
#include "kldmgrd_test.h"

union wire_buffer {
	max_align_t align;
	uint8_t bytes[KLDMGR_MAX_MESSAGE];
};

struct fixture {
	struct service_session *session;
	pid_t child;
};

struct fake_backend {
	int error;
};

static int
fake_load(const char *name __unused, void *argument)
{
	struct fake_backend *fake = argument;

	if (fake->error != 0)
		return (errno = fake->error, -1);
	return (41);
}

static int
fake_find(const char *name __unused, void *argument)
{
	struct fake_backend *fake = argument;

	if (fake->error != 0)
		return (errno = fake->error, -1);
	return (42);
}

static int
fake_unload(int id __unused, void *argument)
{
	struct fake_backend *fake = argument;

	if (fake->error != 0)
		return (errno = fake->error, -1);
	return (0);
}

static int
fake_next(int id, void *argument)
{
	struct fake_backend *fake = argument;

	if (fake->error != 0)
		return (errno = fake->error, -1);
	return (id == 0 ? 7 : 0);
}

static int
fake_stat(int id, struct kld_file_stat *status, void *argument)
{
	struct fake_backend *fake = argument;

	if (fake->error != 0)
		return (errno = fake->error, -1);
	memset(status, 0, sizeof(*status));
	status->version = sizeof(*status);
	status->id = id;
	strlcpy(status->name, "if_test", sizeof(status->name));
	return (0);
}

static struct kldmgrd_backend
backend(struct fake_backend *fake)
{
	return ((struct kldmgrd_backend){
		.load = fake_load, .find = fake_find, .unload = fake_unload,
		.next = fake_next, .stat = fake_stat, .context = fake,
	});
}

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
fixture_create(struct fixture *fixture, bool allowed, int backend_error)
{
	int client, provider;

	memset(fixture, 0, sizeof(*fixture));
	channel_pair(&client, &provider);
	fixture->child = fork();
	ATF_REQUIRE(fixture->child >= 0);
	if (fixture->child == 0) {
		struct fake_backend fake = { .error = backend_error };
		struct kldmgrd_backend operations = backend(&fake);

		close(client);
		_exit(kldmgrd_test_serve(provider, "org.test.kld", allowed,
		    &operations));
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
call(struct fixture *fixture, uint16_t opcode, const void *payload,
    size_t payload_length, const int *fds, size_t nfds,
    union wire_buffer *reply, size_t *lengthp)
{
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;
	union wire_buffer request;
	struct kldmgr_msg *message;

	memset(&request, 0, sizeof(request));
	message = (void *)request.bytes;
	message->magic = KLDMGR_MAGIC;
	message->version = KLDMGR_ABI_VERSION;
	message->opcode = opcode;
	if (payload_length != 0)
		memcpy(message + 1, payload, payload_length);
	outgoing = (struct service_message){
		.size = sizeof(outgoing), .data = request.bytes,
		.length = sizeof(*message) + payload_length,
		.fds = fds, .nfds = nfds,
	};
	memset(&incoming, 0, sizeof(incoming));
	incoming.size = sizeof(incoming);
	incoming.data = reply->bytes;
	incoming.capacity = sizeof(reply->bytes);
	options.timeout_ms = 2000;
	if (service_session_call(fixture->session, &outgoing, &incoming,
	    &options) == -1)
		return (-1);
	*lengthp = incoming.length;
	return (0);
}

static int
reply_status(union wire_buffer *reply, size_t length, uint16_t opcode)
{
	struct kldmgr_msg *message = (void *)reply->bytes;

	ATF_REQUIRE_EQ(0, kldmgr_validate_reply(message, length));
	ATF_REQUIRE_EQ(opcode, message->opcode);
	return (-message->status);
}

ATF_TC(provider_all_operations);
ATF_TC_HEAD(provider_all_operations, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(provider_all_operations, tc)
{
	struct kldmgr_module_request module;
	struct kldmgr_list_reply *list;
	struct kldmgr_id_reply *id;
	union wire_buffer reply;
	struct fixture fixture;
	size_t length;

	fixture_create(&fixture, true, 0);
	memset(&module, 0, sizeof(module));
	strlcpy(module.name, "if_test", sizeof(module.name));
	ATF_REQUIRE_EQ(0, call(&fixture, KLDMGR_OP_LOAD, &module,
	    sizeof(module), NULL, 0, &reply, &length));
	ATF_CHECK_EQ(0, reply_status(&reply, length, KLDMGR_OP_LOAD));
	id = (void *)((struct kldmgr_msg *)(void *)reply.bytes + 1);
	ATF_CHECK_EQ(41, id->id);
	ATF_REQUIRE_EQ(0, call(&fixture, KLDMGR_OP_UNLOAD, &module,
	    sizeof(module), NULL, 0, &reply, &length));
	ATF_CHECK_EQ(0, reply_status(&reply, length, KLDMGR_OP_UNLOAD));
	id = (void *)((struct kldmgr_msg *)(void *)reply.bytes + 1);
	ATF_CHECK_EQ(42, id->id);
	ATF_REQUIRE_EQ(0, call(&fixture, KLDMGR_OP_LIST, NULL, 0, NULL, 0,
	    &reply, &length));
	ATF_CHECK_EQ(0, reply_status(&reply, length, KLDMGR_OP_LIST));
	list = (void *)((struct kldmgr_msg *)(void *)reply.bytes + 1);
	ATF_REQUIRE_EQ(1, list->count);
	ATF_CHECK_STREQ("if_test", list->entries[0].name);
	fixture_destroy(&fixture, 0);
}

ATF_TC(provider_policy_and_backend_errors);
ATF_TC_HEAD(provider_policy_and_backend_errors, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(provider_policy_and_backend_errors, tc)
{
	struct kldmgr_module_request module;
	union wire_buffer reply;
	struct fixture fixture;
	size_t length;

	memset(&module, 0, sizeof(module));
	strlcpy(module.name, "if_test", sizeof(module.name));
	fixture_create(&fixture, false, 0);
	ATF_REQUIRE_EQ(0, call(&fixture, KLDMGR_OP_LOAD, &module,
	    sizeof(module), NULL, 0, &reply, &length));
	ATF_CHECK_EQ(EACCES, reply_status(&reply, length, KLDMGR_OP_LOAD));
	ATF_REQUIRE_EQ(0, call(&fixture, KLDMGR_OP_LIST, NULL, 0, NULL, 0,
	    &reply, &length));
	ATF_CHECK_EQ(EACCES, reply_status(&reply, length, KLDMGR_OP_LIST));
	fixture_destroy(&fixture, 0);

	fixture_create(&fixture, true, EIO);
	ATF_REQUIRE_EQ(0, call(&fixture, KLDMGR_OP_LOAD, &module,
	    sizeof(module), NULL, 0, &reply, &length));
	ATF_CHECK_EQ(EIO, reply_status(&reply, length, KLDMGR_OP_LOAD));
	ATF_REQUIRE_EQ(0, call(&fixture, KLDMGR_OP_LIST, NULL, 0, NULL, 0,
	    &reply, &length));
	ATF_CHECK_EQ(EIO, reply_status(&reply, length, KLDMGR_OP_LIST));
	fixture_destroy(&fixture, 0);
}

ATF_TC(provider_rejects_descriptors);
ATF_TC_HEAD(provider_rejects_descriptors, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(provider_rejects_descriptors, tc)
{
	union wire_buffer reply;
	struct fixture fixture;
	size_t length;
	int fd;

	fixture_create(&fixture, true, 0);
	fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	ATF_REQUIRE(fd >= 0);
	ATF_CHECK(call(&fixture, KLDMGR_OP_LIST, NULL, 0, &fd, 1, &reply,
	    &length) == -1);
	close(fd);
	fixture_destroy(&fixture, 1);
}

ATF_TC_WITHOUT_HEAD(arguments);
ATF_TC_BODY(arguments, tc)
{
	struct fake_backend fake = { 0 };
	struct kldmgrd_backend operations = backend(&fake);

	ATF_CHECK_ERRNO(EINVAL,
	    kldmgrd_test_serve(-1, "test", true, &operations) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    kldmgrd_test_serve(0, "", true, &operations) == -1);
	ATF_CHECK_ERRNO(EINVAL,
	    kldmgrd_test_serve(0, "test", true, NULL) == -1);
}

ATF_TC_WITHOUT_HEAD(worker_channel_crosses_exactly_one_fork);
ATF_TC_BODY(worker_channel_crosses_exactly_one_fork, tc)
{
	pid_t child, grandchild, sibling;
	int fd, status;

	fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, kldmgrd_test_prepare_worker_fd(fd));
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		if (fcntl(fd, F_GETFD) == -1)
			_exit(1);
		grandchild = fork();
		if (grandchild == -1)
			_exit(2);
		if (grandchild == 0)
			_exit(fcntl(fd, F_GETFD) == -1 && errno == EBADF ? 0 : 3);
		if (waitpid(grandchild, &status, 0) != grandchild ||
		    !WIFEXITED(status) || WEXITSTATUS(status) != 0)
			_exit(4);
		_exit(0);
	}
	ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	ATF_CHECK_EQ(0, WEXITSTATUS(status));
	sibling = fork();
	ATF_REQUIRE(sibling >= 0);
	if (sibling == 0)
		_exit(fcntl(fd, F_GETFD) == -1 && errno == EBADF ? 0 : 1);
	ATF_REQUIRE_EQ(sibling, waitpid(sibling, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	ATF_CHECK_EQ(0, WEXITSTATUS(status));
	close(fd);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, provider_all_operations);
	ATF_TP_ADD_TC(tp, provider_policy_and_backend_errors);
	ATF_TP_ADD_TC(tp, provider_rejects_descriptors);
	ATF_TP_ADD_TC(tp, arguments);
	ATF_TP_ADD_TC(tp, worker_channel_crosses_exactly_one_fork);
	return (atf_no_error());
}
