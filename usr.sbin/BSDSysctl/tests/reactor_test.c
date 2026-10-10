/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/socket.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <channel.h>
#include <errno.h>
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
#define SYSCTLCMP_TESTING
#include "../bsdsysctl.c"

static int
request(int fd)
{
	union {
		max_align_t align;
		unsigned char bytes[SYSCTLCMP_MAX_MESSAGE];
	} buffer;
	struct sysctlcmp_msg *msg = (void *)buffer.bytes;
	struct sysctlcmp_body *body = (void *)(msg + 1);
	struct pollfd ready = { .fd = fd, .events = POLLIN };
	const char name[] = "kern.ostype";
	size_t length = sizeof(*msg) + sizeof(*body) + sizeof(name);

	memset(&buffer, 0, sizeof(buffer));
	msg->magic = SYSCTLCMP_MAGIC;
	msg->opcode = SYSCTLCMP_OP_GET;
	body->name_length = sizeof(name);
	memcpy(body + 1, name, sizeof(name));
	ATF_REQUIRE_EQ((ssize_t)length, send(fd, buffer.bytes, length, 0));
	/* An old sequential serve loop would stall for the 10-second idle
	 * limit. */
	ATF_REQUIRE_EQ(1, poll(&ready, 1, 1000));
	ATF_REQUIRE(
	    recv(fd, buffer.bytes, sizeof(buffer), 0) >= (ssize_t)sizeof(*msg));
	return (-msg->status);
}

ATF_TC_WITHOUT_HEAD(idle_and_policy_isolation);
ATF_TC_BODY(idle_and_policy_isolation, tc)
{
	struct sysctlcmp_config config = { 0 };
	const char *labels[] = { "idle", "allowed", "denied" };
	int pairs[3][2], providers[3], status;
	pid_t child;

	config.nclients = 1;
	strlcpy(config.clients[0].label, "allowed",
	    sizeof(config.clients[0].label));
	config.clients[0].acl.nread = 1;
	strlcpy(config.clients[0].acl.read[0], "kern.ostype",
	    SYSCTLCMP_MAX_PREFIX);
	for (unsigned i = 0; i < 3; i++) {
		ATF_REQUIRE_EQ(0,
		    socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pairs[i]));
		providers[i] = pairs[i][1];
	}
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		for (unsigned i = 0; i < 3; i++)
			close(pairs[i][0]);
		_exit(sysctlcmp_test_serve_many(providers, labels, 3, &config,
		    10000));
	}
	for (unsigned i = 0; i < 3; i++)
		close(pairs[i][1]);
	for (unsigned i = 0; i < 4; i++) {
		ATF_CHECK_EQ(0, request(pairs[1][0]));
		ATF_CHECK_EQ(EPERM, request(pairs[2][0]));
	}
	/* Malforming the idle client's request must not stop the other streams.
	 */
	ATF_REQUIRE_EQ(1, send(pairs[0][0], "x", 1, 0));
	ATF_CHECK_EQ(0, request(pairs[1][0]));
	ATF_CHECK_EQ(EPERM, request(pairs[2][0]));
	for (unsigned i = 0; i < 3; i++)
		close(pairs[i][0]);
	ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	ATF_CHECK_EQ(1, WEXITSTATUS(status));
}

ATF_TC(writable_does_not_extend_idle);
ATF_TC_HEAD(writable_does_not_extend_idle, tc)
{
	atf_tc_set_md_var(tc, "timeout", "5");
}
ATF_TC_BODY(writable_does_not_extend_idle, tc)
{
	struct sysctlcmp_config config = { 0 };
	const char *label = "idle";
	int pair[2], status;
	pid_t child;

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair));
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		close(pair[0]);
		force_writable = 1;
		_exit(sysctlcmp_test_serve_many(&pair[1], &label, 1, &config,
		    100));
	}
	close(pair[1]);
	ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	ATF_CHECK_EQ(0, WEXITSTATUS(status));
	close(pair[0]);
}

ATF_TC_WITHOUT_HEAD(admission_bounds_and_reuse);
ATF_TC_BODY(admission_bounds_and_reuse, tc)
{
	struct session sessions[BSDSYSCTL_MAX_SESSIONS] = { 0 };
	struct sysctlcmp_config config = { 0 };
	int peers[BSDSYSCTL_MAX_SESSIONS], pair[2];
	char label[32];

	for (unsigned i = 0; i < BSDSYSCTL_MAX_SESSIONS; i++) {
		snprintf(label, sizeof(label), "label.%u",
		    i / BSDSYSCTL_MAX_LABEL_SESSIONS);
		ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair));
		peers[i] = pair[0];
		ATF_REQUIRE_EQ(0,
		    sessions_admit(sessions, nitems(sessions), pair[1], label,
			&config));
		if (i == BSDSYSCTL_MAX_LABEL_SESSIONS - 1) {
			ATF_REQUIRE_EQ(0,
			    socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair));
			ATF_CHECK_ERRNO(ENOSPC,
			    sessions_admit(sessions, nitems(sessions), pair[1],
				label, &config) == -1);
			ATF_CHECK_ERRNO(EBADF, fcntl(pair[1], F_GETFD) == -1);
			close(pair[0]);
		}
	}
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair));
	ATF_CHECK_ERRNO(ENOSPC,
	    sessions_admit(sessions, nitems(sessions), pair[1], "new.label",
		&config) == -1);
	ATF_CHECK_ERRNO(EBADF, fcntl(pair[1], F_GETFD) == -1);
	close(pair[0]);
	session_close(&sessions[0]);
	close(peers[0]);
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair));
	peers[0] = pair[0];
	ATF_REQUIRE_EQ(0,
	    sessions_admit(sessions, nitems(sessions), pair[1], "new.label",
		&config));
	ATF_CHECK_STREQ("new.label", sessions[0].label);
	for (unsigned i = 0; i < BSDSYSCTL_MAX_SESSIONS; i++) {
		session_close(&sessions[i]);
		close(peers[i]);
	}
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, admission_bounds_and_reuse);
	ATF_TP_ADD_TC(tp, idle_and_policy_isolation);
	ATF_TP_ADD_TC(tp, writable_does_not_extend_idle);
	return (atf_no_error());
}
