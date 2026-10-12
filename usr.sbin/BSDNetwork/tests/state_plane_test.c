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
struct call {
	bool done;
	int error;
	int status;
	int32_t source_error;
	size_t count;
};

static void
info_cb(void *context, int error, struct bsd_network_v1_ProtocolInfo *value)
{
	struct call *c = context;
	c->done = true;
	c->error = error;
	if (error == 0)
		c->status = value->wire_version == NETWORK_STATE_WIRE_VERSION ?
		    0 : EPROTONOSUPPORT;
}

static void
watch_cb(void *context, int error,
    struct bsd_network_v1_NetworkState_Watch_Result *value)
{
	struct call *c = context;
	c->done = true;
	c->error = error;
	if (error != 0)
		return;
	if (value->tag == bsd_network_v1_NetworkState_Watch_Result_err_tag)
		c->status = (int)value->value.err;
	else {
		c->source_error = value->value.response.source_error;
		c->count = value->value.response.interfaces_size;
	}
}

static void
wait_call(struct fidl_bsd_connection *connection, struct call *c)
{
	while (!c->done)
		if (fidl_bsd_connection_poll(connection, 2000) != 0 && !c->done)
			ATF_REQUIRE_MSG(false, "connection failed");
}

ATF_TC_BODY(plane_watch, tc)
{
	struct network_state_server *server;
	struct fidl_bsd_connection *connection;
	struct bsd_network_v1_WatchRequest request = { 1 };
	struct fidl_bsd_empty empty = { 0 };
	struct call info = { 0 }, first = { 0 }, second = { 0 };
	struct kevent event;
	uint32_t txid;
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
		while (server->sessions[0].connection != NULL) {
			if (kevent(kq, NULL, 0, &event, 1, NULL) != 1 ||
			    network_state_server_event(server, &event) != 1)
				_exit(2);
		}
		network_state_server_destroy(server);
		close(kq);
		_exit(0);
	}
	close(provider);
	ATF_REQUIRE_EQ(0, fidl_bsd_connection_create(client, FIDL_BSD_CLIENT,
	    &connection));
	ATF_REQUIRE_EQ(0, bsd_network_v1_NetworkState_GetProtocolInfo(
	    connection, &empty, info_cb, &info, &txid));
	wait_call(connection, &info);
	ATF_REQUIRE_EQ(0, info.status);
	ATF_REQUIRE_EQ(0, bsd_network_v1_NetworkState_Watch(connection,
	    &request, watch_cb, &first, &txid));
	wait_call(connection, &first);
	ATF_REQUIRE_EQ(0, first.status);
	ATF_REQUIRE_EQ(EAGAIN, first.source_error);
	ATF_REQUIRE_EQ(0, first.count);
	ATF_REQUIRE_EQ(0, bsd_network_v1_NetworkState_Watch(connection,
	    &request, watch_cb, &second, &txid));
	wait_call(connection, &second);
	ATF_REQUIRE_EQ(EAGAIN, second.status);
	fidl_bsd_connection_destroy(connection);
	ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	ATF_REQUIRE_EQ(0, WEXITSTATUS(status));
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, plane_watch);
	return (atf_no_error());
}
