/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/socket.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <channel.h>
#include <errno.h>
#include <libservice.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Socket adapter for the real reactor. Plane transport is tested separately. */
struct channel {
	int fd;
	channel_request_handler handler;
	void *argument;
};
struct channel_message {
	struct channel *channel;
	size_t length;
	unsigned char data[16384];
};
static int force_writable;
static int
fake_create(int fd, const struct channel_options *options, struct channel **out)
{
	(void)options;
	*out = calloc(1, sizeof(**out));
	if (*out == NULL)
		return (-1);
	(*out)->fd = fd;
	return (0);
}
static void
fake_destroy(struct channel *c)
{
	close(c->fd);
	free(c);
}
static int
fake_fd(const struct channel *c)
{
	return (c->fd);
}
static int
fake_wants_write(const struct channel *c)
{
	(void)c;
	return (force_writable);
}
static int
fake_handler(struct channel *c, channel_request_handler h, void *arg)
{
	c->handler = h;
	c->argument = arg;
	return (0);
}
static int
fake_flush(struct channel *c)
{
	(void)c;
	return (0);
}
static int
fake_dispatch(struct channel *c)
{
	struct channel_message *m;
	ssize_t n;

	/* Match the channel library's bounded dispatch behavior. */
	for (unsigned i = 0; i < 32; i++) {
		m = calloc(1, sizeof(*m));
		if (m == NULL)
			return (-1);
		n = recv(c->fd, m->data, sizeof(m->data), MSG_DONTWAIT);
		if (n <= 0) {
			free(m);
			if (n == -1 &&
			    (errno == EAGAIN || errno == EWOULDBLOCK))
				return (0);
			return (-1);
		}
		m->channel = c;
		m->length = n;
		c->handler(c, m, c->argument);
	}
	return (0);
}
static int
fake_reply(struct channel_message *m, const struct channel_outgoing *o)
{
	return (send(m->channel->fd, o->data, o->length, MSG_NOSIGNAL) ==
		    (ssize_t)o->length ?
		0 :
		-1);
}
static const void *
fake_data(const struct channel_message *m)
{
	return (m->data);
}
static size_t
fake_length(const struct channel_message *m)
{
	return (m->length);
}
static size_t
fake_fd_count(const struct channel_message *m)
{
	(void)m;
	return (0);
}
static void
fake_free(struct channel_message *m)
{
	free(m);
}
#define channel_create		    fake_create
#define channel_destroy		    fake_destroy
#define channel_fd		    fake_fd
#define channel_wants_write	    fake_wants_write
#define channel_set_request_handler fake_handler
#define channel_flush		    fake_flush
#define channel_dispatch	    fake_dispatch
#define channel_send_reply	    fake_reply
#define channel_message_data	    fake_data
#define channel_message_length	    fake_length
#define channel_message_fd_count    fake_fd_count
#define channel_message_free	    fake_free
static int
fake_harden(int fd, unsigned flags)
{
	(void)fd;
	(void)flags;
	return (0);
}
#define service_harden_fd fake_harden
#define NETWORK_STATE_TESTING
#include "../state.c"

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
static int
add_client(struct network_state_server *s, const char *label)
{
	int pair[2];
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair));
	ATF_REQUIRE_EQ(0, network_state_server_add(s, pair[1], label));
	return (pair[0]);
}
static void
send_watch(int peer, uint32_t timeout)
{
	struct network_state_request q = {
		.header = { .magic = NETWORK_STATE_MAGIC,
		    .version = 1,
		    .opcode = 1 },
		.timeout_ms = timeout
	};
	ATF_REQUIRE_EQ(sizeof(q), send(peer, &q, sizeof(q), 0));
}
static struct network_state_reply
receive_reply(struct network_state_server *s, int peer)
{
	struct network_state_reply reply = { 0 };
	struct pollfd p = { .fd = peer, .events = POLLIN };
	ssize_t length;
	for (unsigned i = 0; i < 100 && poll(&p, 1, 0) == 0; i++)
		drive(s);
	ATF_REQUIRE_EQ(1, poll(&p, 1, 0));
	length = recv(peer, &reply, sizeof(reply), MSG_DONTWAIT);
	ATF_REQUIRE(length > 0);
	ATF_REQUIRE_EQ(0, network_state_validate_reply(&reply, length));
	return (reply);
}
ATF_TC_WITHOUT_HEAD(watch_lifecycle);
ATF_TC_BODY(watch_lifecycle, tc)
{
	struct network_state_server *server;
	struct network_state_snapshot state = { .count = 1,
		.interfaces = { { .index = 1, .mtu = 1500, .name = "em0" } } };
	struct network_state_reply reply;
	int kq = kqueue(), peer;
	uint64_t generation;
	ATF_REQUIRE(kq >= 0);
	ATF_REQUIRE_EQ(0, network_state_server_create(kq, &server));
	peer = add_client(server, "reader");
	send_watch(peer, 0);
	reply = receive_reply(server, peer);
	ATF_CHECK_EQ(EAGAIN, reply.state.source_error);
	ATF_REQUIRE_EQ(1, publish(server, &state));
	send_watch(peer, 0);
	reply = receive_reply(server, peer);
	ATF_CHECK_EQ(1, reply.state.count);
	ATF_CHECK_EQ(1500, reply.state.interfaces[0].mtu);
	generation = reply.state.generation;
	ATF_REQUIRE_EQ(0, publish(server, &state));
	send_watch(peer, 0);
	reply = receive_reply(server, peer);
	ATF_CHECK_EQ(-EAGAIN, reply.header.status);
	/* The duplicate watch must not replace the original pending request. */
	send_watch(peer, NETWORK_STATE_TIMEOUT_INFINITE);
	for (unsigned i = 0; i < 3; i++)
		drive(server);
	send_watch(peer, 0);
	reply = receive_reply(server, peer);
	ATF_CHECK_EQ(-EBUSY, reply.header.status);
	for (unsigned i = 0; i < 1000; i++) {
		state.interfaces[0].mtu = 1501 + i;
		ATF_REQUIRE_EQ(1, publish(server, &state));
	}
	reply = receive_reply(server, peer);
	ATF_CHECK_EQ(generation + 1000, reply.state.generation);
	ATF_CHECK_EQ(2500, reply.state.interfaces[0].mtu);
	send_watch(peer, 1);
	reply = receive_reply(server, peer);
	ATF_CHECK_EQ(-EAGAIN, reply.header.status);
	memset(&state, 0, sizeof(state));
	state.source_error = EIO;
	ATF_REQUIRE_EQ(1, publish(server, &state));
	send_watch(peer, 0);
	reply = receive_reply(server, peer);
	ATF_CHECK_EQ(EIO, reply.state.source_error);
	ATF_CHECK_EQ(0, reply.state.count);
	memset(&state, 0, sizeof(state));
	ATF_REQUIRE_EQ(1, publish(server, &state));
	send_watch(peer, 0);
	reply = receive_reply(server, peer);
	ATF_CHECK_EQ(0, reply.state.source_error);
	ATF_CHECK_EQ(0, reply.state.count);
	close(peer);
	drive(server);
	ATF_CHECK(server->sessions[0].channel == NULL);
	network_state_server_destroy(server);
	close(kq);
}
ATF_TC_WITHOUT_HEAD(admission_and_disconnect);
ATF_TC_BODY(admission_and_disconnect, tc)
{
	struct network_state_server *server;
	int peers[STATE_CLIENTS], pair[2], kq = kqueue();
	char label[32];
	ATF_REQUIRE(kq >= 0);
	ATF_REQUIRE_EQ(0, network_state_server_create(kq, &server));
	for (unsigned i = 0; i < STATE_CLIENTS; i++) {
		snprintf(label, sizeof(label), "label%u",
		    i / STATE_LABEL_CLIENTS);
		peers[i] = add_client(server, label);
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
	/* A malformed client is removed, without affecting other observers. */
	ATF_REQUIRE_EQ(1, send(peers[0], "x", 1, 0));
	for (unsigned i = 0; i < 10 && server->sessions[0].channel != NULL; i++)
		drive(server);
	ATF_CHECK(server->sessions[0].channel == NULL);
	close(peers[0]);
	peers[0] = add_client(server, "new");
	send_watch(peers[1], 0);
	(void)receive_reply(server, peers[1]);
	for (unsigned i = 0; i < STATE_CLIENTS; i++)
		close(peers[i]);
	network_state_server_destroy(server);
	close(kq);
}
ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, watch_lifecycle);
	ATF_TP_ADD_TC(tp, admission_and_disconnect);
	return (atf_no_error());
}
