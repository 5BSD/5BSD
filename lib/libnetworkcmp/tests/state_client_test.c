/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <libservice.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../network_state.c"
struct service_session {
	int fd;
	uint64_t epoch;
};
static unsigned created, closed, calls;
static int fault, error_reply;
static uint32_t last_timeout;
int
service_open(const char *name, int *fd)
{
	int pair[2];
	ATF_REQUIRE_STREQ(NETWORK_STATE_INTERFACE, name);
	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair) == -1)
		return (-1);
	*fd = pair[0];
	close(pair[1]);
	return (0);
}
int
service_harden_fd(int fd, unsigned flags)
{
	(void)fd;
	ATF_CHECK_EQ(0, flags);
	return (0);
}
int
service_session_create(int fd, struct service_session **out)
{
	*out = calloc(1, sizeof(**out));
	if (*out == NULL)
		return (-1);
	(*out)->fd = fd;
	(*out)->epoch = ++created;
	return (0);
}
void
service_session_close(struct service_session *s)
{
	close(s->fd);
	free(s);
	closed++;
}
int
service_session_call(struct service_session *s,
    const struct service_message *out, struct service_reply *in,
    const struct service_call_options *options)
{
	const struct network_state_request *request = out->data;
	struct network_state_reply
	    reply = { .header = { .magic = NETWORK_STATE_MAGIC,
			  .version = 1,
			  .opcode = 1 },
		    .state = { .generation = 1,
			.count = 1,
			.interfaces = {
			    { .index = 1, .mtu = 1500, .name = "em0" } } } };
	ATF_REQUIRE_EQ(0, network_state_validate_request(request, out->length));
	last_timeout = options->timeout_ms;
	calls++;
	if (fault == 1)
		return (errno = ETIMEDOUT, -1);
	if (fault == 2)
		return (errno = EAGAIN, -1);
	reply.state.epoch = s->epoch;
	if (fault == 3)
		reply.state.interfaces[0].reserved[0] = 1;
	if (fault == 4) {
		reply.state.source_error = EIO;
		reply.state.count = 0;
	}
	reply.header.status = -error_reply;
	in->length = error_reply ? sizeof(reply.header) :
				   NETWORK_STATE_REPLY_SIZE(reply.state.count);
	memcpy(in->data, &reply, in->length);
	in->nfds = 0;
	return (0);
}
ATF_TC_WITHOUT_HEAD(reconnect_errors_and_deadlines);
ATF_TC_BODY(reconnect_errors_and_deadlines, tc)
{
	struct network_state_client *client;
	struct network_state_snapshot state, before;
	uint64_t epoch;
	ATF_REQUIRE_EQ(0, network_state_open(&client));
	ATF_REQUIRE_EQ(0, network_state_watch(client, &state, 0));
	ATF_CHECK_EQ(5000, last_timeout);
	ATF_CHECK_STREQ("em0", state.interfaces[0].name);
	epoch = state.epoch;
	before = state;
	error_reply = EAGAIN;
	ATF_CHECK_ERRNO(EAGAIN, network_state_watch(client, &state, 1) == -1);
	ATF_CHECK_EQ(0, closed);
	ATF_CHECK_EQ(0, memcmp(&before, &state, sizeof(state)));
	error_reply = 0;
	fault = 2;
	ATF_CHECK_ERRNO(EAGAIN, network_state_watch(client, &state, 0) == -1);
	ATF_CHECK_EQ(1,
	    closed); /* A transport error cannot leave an orphan watch. */
	fault = 0;
	ATF_REQUIRE_EQ(0, network_state_watch(client, &state, UINT32_MAX - 2));
	ATF_CHECK_EQ(UINT32_MAX - 1, last_timeout);
	ATF_CHECK(state.epoch != epoch);
	before = state;
	fault = 3;
	ATF_CHECK_ERRNO(EPROTO, network_state_watch(client, &state, 0) == -1);
	ATF_CHECK_EQ(2, closed);
	ATF_CHECK_EQ(0, memcmp(&before, &state, sizeof(state)));
	fault = 1;
	ATF_CHECK_ERRNO(ETIMEDOUT,
	    network_state_watch(client, &state, 1) == -1);
	ATF_CHECK_EQ(3, closed);
	fault = 4;
	ATF_REQUIRE_EQ(0,
	    network_state_watch(client, &state,
		NETWORK_STATE_TIMEOUT_INFINITE));
	ATF_CHECK_EQ(SERVICE_CLIENT_TIMEOUT_INFINITE, last_timeout);
	ATF_CHECK_EQ(EIO, state.source_error);
	ATF_CHECK_EQ(0, state.count);
	network_state_close(client);
}
ATF_TC_WITHOUT_HEAD(wire_and_fork);
ATF_TC_BODY(wire_and_fork, tc)
{
	struct network_state_client *client;
	struct network_state_snapshot state;
	struct network_state_request request = {
		.header = { .magic = NETWORK_STATE_MAGIC,
		    .version = 1,
		    .opcode = 1 }
	};
	struct network_state_reply reply = {
		.header = { .magic = NETWORK_STATE_MAGIC,
		    .version = 1,
		    .opcode = 1 },
		.state = { .epoch = 1, .generation = 1 }
	};
	pid_t child;
	int status;
	ATF_CHECK_EQ(0,
	    network_state_validate_request(&request, sizeof(request)));
	request.reserved = 1;
	ATF_CHECK_ERRNO(EPROTO,
	    network_state_validate_request(&request, sizeof(request)) == -1);
	ATF_CHECK_EQ(0,
	    network_state_validate_reply(&reply, NETWORK_STATE_REPLY_SIZE(0)));
	reply.state.source_error = -1;
	ATF_CHECK_ERRNO(EPROTO,
	    network_state_validate_reply(&reply, NETWORK_STATE_REPLY_SIZE(0)) ==
		-1);
	reply.state.source_error = EIO;
	reply.state.count = 1;
	ATF_CHECK_ERRNO(EPROTO,
	    network_state_validate_reply(&reply, NETWORK_STATE_REPLY_SIZE(1)) ==
		-1);
	ATF_REQUIRE_EQ(0, network_state_open(&client));
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0)
		_exit(network_state_watch(client, &state, 0) == -1 &&
			    errno == ECHILD ?
			0 :
			1);
	ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
	ATF_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	network_state_close(client);
}
ATF_TC_WITHOUT_HEAD(interface_wire_validation);
ATF_TC_BODY(interface_wire_validation, tc)
{
	struct network_state_reply good = {
		.header = { .magic = NETWORK_STATE_MAGIC,
		    .version = 1,
		    .opcode = 1 },
		.state = { .epoch = 1,
		    .generation = 1,
		    .count = 2,
		    .interfaces = { { .index = 1, .name = "em0" },
			{ .index = 2, .name = "lo0" } } }
	};
	struct network_state_reply bad;
	size_t length = NETWORK_STATE_REPLY_SIZE(2);

	ATF_REQUIRE_EQ(0, network_state_validate_reply(&good, length));
	for (unsigned variant = 0; variant < 9; variant++) {
		bad = good;
		switch (variant) {
		case 0:
			bad.state.interfaces[1].index = 1;
			break;
		case 1:
			bad.state.interfaces[0].index = 0;
			break;
		case 2:
			memcpy(bad.state.interfaces[1].name, "em0", 4);
			break;
		case 3:
			bad.state.interfaces[0].name[4] = 'x';
			break;
		case 4:
			memset(bad.state.interfaces[0].name, 'x', 16);
			break;
		case 5:
			bad.state.interfaces[0].reserved[0] = 1;
			break;
		case 6:
			bad.state.interfaces[0].link_state = 3;
			break;
		case 7:
			bad.state.count = NETWORK_STATE_MAX_INTERFACES + 1;
			break;
		case 8:
			bad.state.epoch = 0;
			break;
		}
		ATF_CHECK_ERRNO(EPROTO,
		    network_state_validate_reply(&bad, length) == -1);
	}
	ATF_CHECK_ERRNO(EPROTO,
	    network_state_validate_reply(&good, length - 1) == -1);
	ATF_CHECK_ERRNO(EPROTO,
	    network_state_validate_reply(&good, length + 1) == -1);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, reconnect_errors_and_deadlines);
	ATF_TP_ADD_TC(tp, wire_and_fork);
	ATF_TP_ADD_TC(tp, interface_wire_validation);
	return (atf_no_error());
}
