/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/ioctl.h>
#include <sys/wait.h>

#include <dev/mac_capability/mac_capability_channel_proto.h>
#include <dev/mac_capability/mac_capability_ioctl.h>

#include <atf-c.h>
#include <libservice.h>
#define NETWORK_STATE_TESTING
#include "../state.c"
static int
capability_connect(const char *name)
{
	struct mac_capability_connect_args connect;
	int control, error;

	control = open("/dev/mac_capability", O_RDWR | O_CLOEXEC);
	/*
	 * Plane-on tier only: absent off the plane, and claimed by Capsule on a
	 * live plane unless the image boots with
	 * kern.mac_capability_isolation.enforce=0.  Skip naming the cause.
	 */
	if (control < 0)
		atf_tc_skip(
		    "capability plane unavailable: /dev/mac_capability: "
		    "%s",
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

ATF_TC(plane_watch);
ATF_TC_HEAD(plane_watch, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "15");
}
ATF_TC_BODY(plane_watch, tc)
{
	struct network_state_server *server;
	struct service_session *session;
	struct network_state_request request = {
		.header = { .magic = NETWORK_STATE_MAGIC,
		    .version = 1,
		    .opcode = 1 },
		.timeout_ms = 1
	};
	struct network_state_reply reply;
	struct service_message message = { .size = sizeof(message),
		.data = &request,
		.length = sizeof(request) };
	struct service_reply response = { .size = sizeof(response),
		.data = &reply,
		.capacity = sizeof(reply) };
	struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
	struct kevent event;
	pid_t child;
	int client, provider, kq, status;

	channel_pair(&client, &provider);
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		close(client);
		kq = kqueue();
		if (kq == -1 ||
		    network_state_server_create(kq, &server) == -1 ||
		    network_state_server_add(server, provider,
			"org.test.state") == -1)
			_exit(1);
		while (server->sessions[0].channel != NULL) {
			if (kevent(kq, NULL, 0, &event, 1, NULL) != 1 ||
			    network_state_server_event(server, &event) != 1)
				_exit(2);
		}
		network_state_server_destroy(server);
		close(kq);
		_exit(0);
	}
	close(provider);
	ATF_REQUIRE_EQ(0, service_session_create(client, &session));
	options.timeout_ms = 2000;
	ATF_REQUIRE_EQ(0,
	    service_session_call(session, &message, &response, &options));
	ATF_REQUIRE_EQ(0,
	    network_state_validate_reply(&reply, response.length));
	ATF_REQUIRE_EQ(0, reply.header.status);
	ATF_REQUIRE_EQ(EAGAIN, reply.state.source_error);
	ATF_REQUIRE_EQ(0, reply.state.count);
	ATF_REQUIRE_EQ(0,
	    service_session_call(session, &message, &response, &options));
	ATF_REQUIRE_EQ(0,
	    network_state_validate_reply(&reply, response.length));
	ATF_REQUIRE_EQ(-EAGAIN, reply.header.status);
	service_session_close(session);
	ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	ATF_REQUIRE_EQ(0, WEXITSTATUS(status));
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, plane_watch);
	return (atf_no_error());
}
