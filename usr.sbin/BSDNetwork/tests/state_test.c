/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * The system.Network.State reactor (state.c) driven in-process over real
 * capability channels: each test client is a bsd.network.v1 NetworkState
 * connection built from the generated bindings.  Plane-on tier: without
 * /dev/mac_capability the cases skip.
 */
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <dev/mac_capability/mac_capability_channel_proto.h>
#include <dev/mac_capability/mac_capability_ioctl.h>

#include <atf-c.h>
#include <errno.h>
#include <libservice.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NETWORK_STATE_TESTING
#include "../state.c"

static int
capability_connect(const char *name)
{
	struct mac_capability_connect_args connect;
	int control, error;

	control = open("/dev/mac_capability", O_RDWR | O_CLOEXEC);
	if (control < 0)
		atf_tc_skip("capability plane unavailable: /dev/mac_capability: "
		    "%s", strerror(errno));
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

struct peer {
	struct fidl_bsd_connection *connection;
	int fd;		/* raw client descriptor, for hand-built frames */
};

struct watch {
	bool done;
	int error;	/* transport */
	int status;	/* application errno */
	uint64_t epoch;
	uint64_t generation;
	int32_t source_error;
	size_t count;
	uint32_t mtu;
};

static void
drive(struct network_state_server *s)
{
	struct kevent event;
	struct timespec timeout = { .tv_nsec = 10000000 };
	int n = kevent(s->kq, NULL, 0, &event, 1, &timeout);
	ATF_REQUIRE(n >= 0);
	if (n == 1)
		ATF_REQUIRE_EQ(1, network_state_server_event(s, &event));
}

/* Run both ends until the call completes. */
static void
settle(struct network_state_server *s, struct peer *peer, const bool *done)
{
	for (unsigned i = 0; i < 500 && !*done; i++) {
		drive(s);
		(void)fidl_bsd_connection_poll(peer->connection, 0);
	}
	ATF_REQUIRE(*done);
}

static void
info_cb(void *context, int error, struct bsd_network_v1_ProtocolInfo *value)
{
	struct watch *w = context;
	w->done = true;
	w->error = error;
	if (error == 0)
		w->status = value->wire_version == NETWORK_STATE_WIRE_VERSION ?
		    0 : EPROTONOSUPPORT;
}

static void
watch_cb(void *context, int error,
    struct bsd_network_v1_NetworkState_Watch_Result *value)
{
	struct watch *w = context;
	w->done = true;
	w->error = error;
	if (error != 0)
		return;
	if (value->tag == bsd_network_v1_NetworkState_Watch_Result_err_tag) {
		w->status = (int)value->value.err;
		return;
	}
	w->epoch = value->value.response.epoch;
	w->generation = value->value.response.generation;
	w->source_error = value->value.response.source_error;
	w->count = value->value.response.interfaces_size;
	w->mtu = w->count != 0 ? value->value.response.interfaces[0].mtu : 0;
}

static void
add_peer(struct network_state_server *s, const char *label, struct peer *peer,
    bool negotiate)
{
	struct fidl_bsd_empty empty = { 0 };
	struct watch info = { 0 };
	uint32_t txid;
	int provider;

	channel_pair(&peer->fd, &provider);
	ATF_REQUIRE_EQ(0, network_state_server_add(s, provider, label));
	ATF_REQUIRE_EQ(0, fidl_bsd_connection_create(dup(peer->fd),
	    FIDL_BSD_CLIENT, &peer->connection));
	if (!negotiate)
		return;
	ATF_REQUIRE_EQ(0, bsd_network_v1_NetworkState_GetProtocolInfo(
	    peer->connection, &empty, info_cb, &info, &txid));
	settle(s, peer, &info.done);
	ATF_REQUIRE_EQ(0, info.error);
	ATF_REQUIRE_EQ(0, info.status);
}

static void
close_peer(struct peer *peer)
{
	if (peer->connection != NULL)
		fidl_bsd_connection_destroy(peer->connection);
	if (peer->fd >= 0)
		close(peer->fd);
	peer->connection = NULL;
	peer->fd = -1;
}

static void
start_watch(struct peer *peer, uint32_t timeout, struct watch *w)
{
	struct bsd_network_v1_WatchRequest request = { timeout };
	uint32_t txid;

	memset(w, 0, sizeof(*w));
	ATF_REQUIRE_EQ(0, bsd_network_v1_NetworkState_Watch(peer->connection,
	    &request, watch_cb, w, &txid));
}

static struct watch
do_watch(struct network_state_server *s, struct peer *peer, uint32_t timeout)
{
	struct watch w;

	start_watch(peer, timeout, &w);
	settle(s, peer, &w.done);
	ATF_REQUIRE_EQ(0, w.error);
	return (w);
}

ATF_TC(watch_lifecycle);
ATF_TC_HEAD(watch_lifecycle, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(watch_lifecycle, tc)
{
	struct network_state_server *server;
	struct network_state_snapshot state = { .count = 1,
		.interfaces = { { .index = 1, .mtu = 1500, .name = "em0" } } };
	struct watch reply, pending, busy;
	struct peer peer;
	int kq = kqueue();
	uint64_t generation;

	ATF_REQUIRE(kq >= 0);
	ATF_REQUIRE_EQ(0, network_state_server_create(kq, &server));
	add_peer(server, "reader", &peer, true);
	reply = do_watch(server, &peer, 0);
	ATF_CHECK_EQ(0, reply.status);
	ATF_CHECK_EQ(EAGAIN, reply.source_error);
	ATF_REQUIRE_EQ(1, publish(server, &state));
	reply = do_watch(server, &peer, 0);
	ATF_CHECK_EQ(1, reply.count);
	ATF_CHECK_EQ(1500, reply.mtu);
	generation = reply.generation;
	ATF_REQUIRE_EQ(0, publish(server, &state));
	reply = do_watch(server, &peer, 0);
	ATF_CHECK_EQ(EAGAIN, reply.status);
	/* An overlapping watch does not replace the pending one. */
	start_watch(&peer, NETWORK_STATE_TIMEOUT_INFINITE, &pending);
	for (unsigned i = 0; i < 5; i++) {
		(void)fidl_bsd_connection_poll(peer.connection, 0);
		drive(server);
	}
	ATF_REQUIRE(server->sessions[0].pending != NULL);
	busy = do_watch(server, &peer, 0);
	ATF_CHECK_EQ(EBUSY, busy.status);
	ATF_CHECK(!pending.done);
	/* Changes coalesce into the pending watch. */
	for (unsigned i = 0; i < 1000; i++) {
		state.interfaces[0].mtu = 1501 + i;
		ATF_REQUIRE_EQ(1, publish(server, &state));
	}
	settle(server, &peer, &pending.done);
	ATF_CHECK_EQ(generation + 1000, pending.generation);
	ATF_CHECK_EQ(2500, pending.mtu);
	reply = do_watch(server, &peer, 1);
	ATF_CHECK_EQ(EAGAIN, reply.status);
	memset(&state, 0, sizeof(state));
	state.source_error = EIO;
	ATF_REQUIRE_EQ(1, publish(server, &state));
	reply = do_watch(server, &peer, 0);
	ATF_CHECK_EQ(EIO, reply.source_error);
	ATF_CHECK_EQ(0, reply.count);
	memset(&state, 0, sizeof(state));
	ATF_REQUIRE_EQ(1, publish(server, &state));
	reply = do_watch(server, &peer, 0);
	ATF_CHECK_EQ(0, reply.source_error);
	ATF_CHECK_EQ(0, reply.count);
	close_peer(&peer);
	for (unsigned i = 0; i < 10 && server->sessions[0].connection != NULL; i++)
		drive(server);
	ATF_CHECK(server->sessions[0].connection == NULL);
	network_state_server_destroy(server);
	close(kq);
}

ATF_TC(admission_and_protocol);
ATF_TC_HEAD(admission_and_protocol, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr", "Per-label and total admission limits; "
	    "a session that watches before negotiating, or sends a pre-FIDL "
	    "record, is dropped without affecting the others");
}
ATF_TC_BODY(admission_and_protocol, tc)
{
	static struct peer peers[STATE_CLIENTS];
	struct network_state_server *server;
	struct network_state_request legacy = {
		.header = { .magic = NETWORK_STATE_MAGIC, .version = 1,
		    .opcode = 1 }
	};
	struct watch w;
	int pair[2], kq = kqueue();
	char label[32];

	ATF_REQUIRE(kq >= 0);
	ATF_REQUIRE_EQ(0, network_state_server_create(kq, &server));
	for (unsigned i = 0; i < STATE_CLIENTS; i++) {
		snprintf(label, sizeof(label), "label%u",
		    i / STATE_LABEL_CLIENTS);
		add_peer(server, label, &peers[i], false);
		if (i == STATE_LABEL_CLIENTS - 1) {
			ATF_REQUIRE_EQ(0,
			    socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair));
			ATF_CHECK_ERRNO(ENOSPC,
			    network_state_server_add(server, pair[1], label) ==
			    -1);
			ATF_CHECK_ERRNO(EBADF, fcntl(pair[1], F_GETFD) == -1);
			close(pair[0]);
		}
	}
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair));
	ATF_CHECK_ERRNO(ENOSPC,
	    network_state_server_add(server, pair[1], "new") == -1);
	close(pair[0]);
	/* A Watch before GetProtocolInfo ends only that session. */
	start_watch(&peers[0], 0, &w);
	settle(server, &peers[0], &w.done);
	ATF_CHECK(w.error != 0);
	ATF_CHECK(server->sessions[0].connection == NULL);
	/* So does a pre-FIDL record. */
	{
		struct service_session *session;
		struct service_message message = { .size = sizeof(message),
			.data = &legacy, .length = sizeof(legacy) };
		uint8_t buffer[64];
		struct service_reply response = { .size = sizeof(response),
			.data = buffer, .capacity = sizeof(buffer) };
		struct service_call_options options =
		    SERVICE_CALL_OPTIONS_INITIALIZER;

		fidl_bsd_connection_destroy(peers[1].connection);
		peers[1].connection = NULL;
		ATF_REQUIRE_EQ(0, service_session_create(peers[1].fd,
		    &session));
		peers[1].fd = -1;
		options.timeout_ms = 50;
		for (unsigned i = 0; i < 20 &&
		    server->sessions[1].connection != NULL; i++) {
			(void)service_session_call(session, &message, &response,
			    &options);
			drive(server);
		}
		service_session_close(session);
	}
	ATF_CHECK(server->sessions[1].connection == NULL);
	close_peer(&peers[0]);
	add_peer(server, "new", &peers[0], true);
	w = do_watch(server, &peers[0], 0);
	ATF_CHECK_EQ(0, w.status);
	for (unsigned i = 0; i < STATE_CLIENTS; i++)
		close_peer(&peers[i]);
	network_state_server_destroy(server);
	close(kq);
}

ATF_TC(idle_expiry);
ATF_TC_HEAD(idle_expiry, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "descr", "An idle session expires; a peer that "
	    "leaves with a watch pending is dropped without affecting another");
}
ATF_TC_BODY(idle_expiry, tc)
{
	struct network_state_server *server;
	struct peer leaving, healthy;
	struct watch pending, w;
	int kq = kqueue();

	ATF_REQUIRE(kq >= 0);
	ATF_REQUIRE_EQ(0, network_state_server_create(kq, &server));
	add_peer(server, "leaving", &leaving, true);
	add_peer(server, "healthy", &healthy, true);
	(void)do_watch(server, &leaving, 0);
	start_watch(&leaving, NETWORK_STATE_TIMEOUT_INFINITE, &pending);
	for (unsigned i = 0; i < 10 && server->sessions[0].pending == NULL; i++) {
		(void)fidl_bsd_connection_poll(leaving.connection, 0);
		drive(server);
	}
	ATF_REQUIRE(server->sessions[0].pending != NULL);
	close_peer(&leaving);
	for (unsigned i = 0; i < 10 && server->sessions[0].connection != NULL; i++)
		drive(server);
	ATF_CHECK(server->sessions[0].connection == NULL);
	w = do_watch(server, &healthy, 0);
	ATF_CHECK_EQ(0, w.status);
	/* Shorten only the fixture's idle timer. */
	ATF_REQUIRE_EQ(0, arm_timer(&server->sessions[1], 1));
	for (unsigned i = 0; i < 100 && server->sessions[1].connection != NULL;
	    i++) {
		drive(server);
		usleep(1000);
	}
	ATF_CHECK(server->sessions[1].connection == NULL);
	close_peer(&healthy);
	network_state_server_destroy(server);
	close(kq);
}

ATF_TC(restart_and_pending_teardown);
ATF_TC_HEAD(restart_and_pending_teardown, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(restart_and_pending_teardown, tc)
{
	struct network_state_server *server;
	struct watch first, pending;
	struct peer peer;
	uint64_t epoch = 0;
	int kq = kqueue();

	ATF_REQUIRE(kq >= 0);
	for (unsigned cycle = 0; cycle < 50; cycle++) {
		ATF_REQUIRE_EQ(0, network_state_server_create(kq, &server));
		add_peer(server, "repeat", &peer, true);
		first = do_watch(server, &peer, 0);
		/* Every server instance starts a new epoch. */
		ATF_CHECK(first.epoch != epoch);
		epoch = first.epoch;
		start_watch(&peer, NETWORK_STATE_TIMEOUT_INFINITE, &pending);
		for (unsigned i = 0; i < 10 &&
		    server->sessions[0].pending == NULL; i++) {
			(void)fidl_bsd_connection_poll(peer.connection, 0);
			drive(server);
		}
		ATF_REQUIRE(server->sessions[0].pending != NULL);
		network_state_server_destroy(server);
		/* The pending watch fails: the provider is gone. */
		for (unsigned i = 0; i < 100 && !pending.done; i++)
			(void)fidl_bsd_connection_poll(peer.connection, 10);
		ATF_CHECK(pending.done && pending.error != 0);
		close_peer(&peer);
	}
	close(kq);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, idle_expiry);
	ATF_TP_ADD_TC(tp, restart_and_pending_teardown);
	ATF_TP_ADD_TC(tp, watch_lifecycle);
	ATF_TP_ADD_TC(tp, admission_and_protocol);
	return (atf_no_error());
}
