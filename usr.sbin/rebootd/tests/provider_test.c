/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/reboot.h>
#include <sys/wait.h>

#include <dev/mac_capability/mac_capability_channel_proto.h>
#include <dev/mac_capability/mac_capability_ioctl.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libservice.h>
#include <rebootctl.h>
#include <rebootctl_server.h>

#include "rebootd_ops.h"
#include "rebootd_test.h"

union wire_buffer {
	max_align_t align;
	uint8_t bytes[REBOOTCTL_MAX_MESSAGE];
};

struct fixture {
	struct service_session *session;
	pid_t child;
};

struct fake_backend {
	int error;
};

static int
fake_reboot(int howto __unused, void *argument)
{
	struct fake_backend *fake = argument;

	if (fake->error != 0)
		return (errno = fake->error, -1);
	return (0);
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
fixture_create(struct fixture *fixture, bool allowed, int backend_error,
    bool initially_pending)
{
	int client, provider;

	memset(fixture, 0, sizeof(*fixture));
	channel_pair(&client, &provider);
	fixture->child = fork();
	ATF_REQUIRE(fixture->child >= 0);
	if (fixture->child == 0) {
		struct fake_backend fake = { .error = backend_error };
		struct rebootd_backend operations = {
			.reboot = fake_reboot, .context = &fake,
		};
		_Atomic bool pending;

		atomic_init(&pending, initially_pending);
		close(client);
		_exit(rebootd_test_serve(provider, "org.test.reboot", allowed,
		    &pending, &operations));
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
call(struct fixture *fixture, uint16_t opcode, uint32_t howto,
    const int *fds, size_t nfds, union wire_buffer *reply, size_t *lengthp)
{
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct service_message outgoing;
	struct service_reply incoming;
	union wire_buffer request;
	struct rebootctl_request *operation;
	struct rebootctl_msg *message;
	size_t length;

	memset(&request, 0, sizeof(request));
	message = (void *)request.bytes;
	message->magic = REBOOTCTL_MAGIC;
	message->version = REBOOTCTL_ABI_VERSION;
	message->opcode = opcode;
	length = sizeof(*message);
	if (opcode != REBOOTCTL_OP_STATUS) {
		operation = (void *)(message + 1);
		operation->howto = howto;
		length += sizeof(*operation);
	}
	outgoing = (struct service_message){
		.size = sizeof(outgoing), .data = request.bytes, .length = length,
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
	struct rebootctl_msg *message = (void *)reply->bytes;

	ATF_REQUIRE_EQ(0, rebootctl_validate_reply(message, length));
	ATF_REQUIRE_EQ(opcode, message->opcode);
	return (-message->status);
}

ATF_TC(provider_operations_and_state);
ATF_TC_HEAD(provider_operations_and_state, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(provider_operations_and_state, tc)
{
	struct rebootctl_status_reply *status;
	union wire_buffer reply;
	struct fixture fixture;
	size_t length;

	fixture_create(&fixture, true, 0, false);
	ATF_REQUIRE_EQ(0, call(&fixture, REBOOTCTL_OP_STATUS, 0, NULL, 0,
	    &reply, &length));
	ATF_CHECK_EQ(0, reply_status(&reply, length, REBOOTCTL_OP_STATUS));
	status = (void *)((struct rebootctl_msg *)(void *)reply.bytes + 1);
	ATF_CHECK_EQ(0, status->pending);
	ATF_REQUIRE_EQ(0, call(&fixture, REBOOTCTL_OP_REBOOT, RB_REROOT,
	    NULL, 0, &reply, &length));
	ATF_CHECK_EQ(0, reply_status(&reply, length, REBOOTCTL_OP_REBOOT));
	ATF_REQUIRE_EQ(0, call(&fixture, REBOOTCTL_OP_STATUS, 0, NULL, 0,
	    &reply, &length));
	ATF_CHECK_EQ(0, reply_status(&reply, length, REBOOTCTL_OP_STATUS));
	status = (void *)((struct rebootctl_msg *)(void *)reply.bytes + 1);
	ATF_CHECK_EQ(1, status->pending);
	ATF_REQUIRE_EQ(0, call(&fixture, REBOOTCTL_OP_SHUTDOWN, 0, NULL, 0,
	    &reply, &length));
	ATF_CHECK_EQ(EALREADY,
	    reply_status(&reply, length, REBOOTCTL_OP_SHUTDOWN));
	fixture_destroy(&fixture, 0);
}

ATF_TC(provider_policy_and_backend_errors);
ATF_TC_HEAD(provider_policy_and_backend_errors, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(provider_policy_and_backend_errors, tc)
{
	struct rebootctl_status_reply *status;
	union wire_buffer reply;
	struct fixture fixture;
	size_t length;

	fixture_create(&fixture, false, 0, false);
	ATF_REQUIRE_EQ(0, call(&fixture, REBOOTCTL_OP_REBOOT, 0, NULL, 0,
	    &reply, &length));
	ATF_CHECK_EQ(EACCES,
	    reply_status(&reply, length, REBOOTCTL_OP_REBOOT));
	ATF_REQUIRE_EQ(0, call(&fixture, REBOOTCTL_OP_STATUS, 0, NULL, 0,
	    &reply, &length));
	ATF_CHECK_EQ(0, reply_status(&reply, length, REBOOTCTL_OP_STATUS));
	fixture_destroy(&fixture, 0);

	fixture_create(&fixture, true, EIO, false);
	ATF_REQUIRE_EQ(0, call(&fixture, REBOOTCTL_OP_SHUTDOWN, 0, NULL, 0,
	    &reply, &length));
	ATF_CHECK_EQ(EIO,
	    reply_status(&reply, length, REBOOTCTL_OP_SHUTDOWN));
	ATF_REQUIRE_EQ(0, call(&fixture, REBOOTCTL_OP_STATUS, 0, NULL, 0,
	    &reply, &length));
	status = (void *)((struct rebootctl_msg *)(void *)reply.bytes + 1);
	ATF_CHECK_EQ(0, status->pending);
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

	fixture_create(&fixture, true, 0, false);
	fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	ATF_REQUIRE(fd >= 0);
	ATF_CHECK(call(&fixture, REBOOTCTL_OP_STATUS, 0, &fd, 1, &reply,
	    &length) == -1);
	close(fd);
	fixture_destroy(&fixture, 1);
}

ATF_TC_WITHOUT_HEAD(arguments);
ATF_TC_BODY(arguments, tc)
{
	struct rebootd_backend operations = {
		.reboot = fake_reboot, .context = &(struct fake_backend){ 0 },
	};
	_Atomic bool pending;

	atomic_init(&pending, false);
	ATF_CHECK_ERRNO(EINVAL, rebootd_test_serve(-1, "test", true,
	    &pending, &operations) == -1);
	ATF_CHECK_ERRNO(EINVAL, rebootd_test_serve(0, "", true,
	    &pending, &operations) == -1);
	ATF_CHECK_ERRNO(EINVAL, rebootd_test_serve(0, "test", true, NULL,
	    &operations) == -1);
	ATF_CHECK_ERRNO(EINVAL, rebootd_test_serve(0, "test", true,
	    &pending, NULL) == -1);
}

ATF_TC_WITHOUT_HEAD(scheduler_disarms_before_reboot);
ATF_TC_BODY(scheduler_disarms_before_reboot, tc)
{
	unsigned persist_order, reboot_order;
	bool pending;

	ATF_CHECK_ERRNO(EIO, rebootd_test_scheduler_tick(0, EIO,
	    &persist_order, &reboot_order, &pending) == -1);
	ATF_CHECK_EQ(1U, persist_order);
	ATF_CHECK_EQ(2U, reboot_order);
	ATF_CHECK(!pending);
}

ATF_TC_WITHOUT_HEAD(scheduler_never_reboots_without_durable_disarm);
ATF_TC_BODY(scheduler_never_reboots_without_durable_disarm, tc)
{
	unsigned persist_order, reboot_order;
	bool pending;

	ATF_CHECK_ERRNO(ENOSPC, rebootd_test_scheduler_tick(ENOSPC, 0,
	    &persist_order, &reboot_order, &pending) == -1);
	ATF_CHECK_EQ(1U, persist_order);
	ATF_CHECK_EQ(0U, reboot_order);
	ATF_CHECK(pending);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, provider_operations_and_state);
	ATF_TP_ADD_TC(tp, provider_policy_and_backend_errors);
	ATF_TP_ADD_TC(tp, provider_rejects_descriptors);
	ATF_TP_ADD_TC(tp, arguments);
	ATF_TP_ADD_TC(tp, scheduler_disarms_before_reboot);
	ATF_TP_ADD_TC(tp, scheduler_never_reboots_without_durable_disarm);
	return (atf_no_error());
}
