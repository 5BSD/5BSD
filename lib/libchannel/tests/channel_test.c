/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/wait.h>

#include <dev/mac_capability/mac_capability_channel_proto.h>
#include <dev/mac_capability/mac_capability_ioctl.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>
#include <channel.h>

#define	OUT(_data, _length)						\
	(&(struct channel_outgoing)					\
	CHANNEL_OUTGOING_INITIALIZER((_data), (_length)))
#define	OUT_FDS(_data, _length, _fds, _nfds)				\
	(&(struct channel_outgoing){					\
	    .size = sizeof(struct channel_outgoing),			\
	    .data = (_data),						\
	    .length = (_length),					\
	    .fds = (_fds),						\
	    .nfds = (_nfds)						\
	})

struct exchange_state {
	unsigned requests;
	unsigned replies;
	unsigned events;
	unsigned canceled;
	int taken_fd;
};

struct reorder_state {
	struct channel_message *held[2];
	unsigned requests;
	unsigned replies;
	unsigned reply_order[2];
	unsigned errors;
};

struct reply_expectation {
	struct reorder_state *state;
	const char *payload;
	size_t length;
	unsigned ordinal;
};

struct terminal_state {
	unsigned callbacks;
	int error;
};

static int
capability_connect(const char *name)
{
	struct mac_capability_connect_args connect;
	int control, error;

	control = open("/dev/mac_capability", O_RDWR);
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
capability_channel_pair(int *first, int *second)
{
	struct mac_capability_recvmsg_args receive;
	struct mac_capability_sendmsg_args send;
	uint32_t op;

	*first = capability_connect("channel");
	ATF_REQUIRE_MSG(*first >= 0, "connect channel: %s", strerror(errno));
	op = CHANNEL_OP_CREATE;
	memset(&send, 0, sizeof(send));
	send.payload = &op;
	send.payload_len = sizeof(op);
	ATF_REQUIRE(ioctl(*first, MAC_CAPABILITY_SENDMSG, &send) == 0);
	memset(&receive, 0, sizeof(receive));
	receive.fds = second;
	receive.nfds = 1;
	ATF_REQUIRE(ioctl(*first, MAC_CAPABILITY_RECVMSG, &receive) == 0);
	ATF_REQUIRE_EQ(1, receive.nfds);
}

static int
dispatch_wait(struct channel *channel)
{
	int ready;

	/*
	 * Channels are kqueue-only; wait via channel_wait, not poll(2).  A
	 * dead/EOF channel reports readable so the following channel_dispatch
	 * observes the terminal error.
	 */
	ready = channel_wait(channel, 0, 5000);
	ATF_REQUIRE_MSG(ready > 0, "channel readiness: %s",
	    ready == 0 ? "timed out" : strerror(errno));
	return (channel_dispatch(channel));
}

static void
reply_handler(struct channel_request *request, struct channel_message *reply,
    int error, void *argument)
{
	struct exchange_state *state;

	state = argument;
	if (error == ECANCELED) {
		state->canceled++;
		ATF_CHECK(reply == NULL);
	} else {
		ATF_CHECK_EQ(0, error);
		ATF_REQUIRE(reply != NULL);
		ATF_CHECK_EQ(CHANNEL_MESSAGE_REPLY,
		    channel_message_kind(reply));
		ATF_CHECK_EQ(5, channel_message_length(reply));
		ATF_CHECK(memcmp(channel_message_data(reply), "reply", 5) == 0);
		state->replies++;
		channel_message_free(reply);
	}
	channel_request_release(request);
}

static void
request_handler(struct channel *channel, struct channel_message *request,
    void *argument)
{
	struct exchange_state *state;

	(void)channel;
	state = argument;
	ATF_CHECK_EQ(CHANNEL_MESSAGE_REQUEST,
	    channel_message_kind(request));
	ATF_CHECK(channel_message_token(request) != 0);
	ATF_CHECK_EQ(7, channel_message_length(request));
	ATF_CHECK(memcmp(channel_message_data(request), "request", 7) == 0);
	state->requests++;
	ATF_REQUIRE(channel_send_reply(request, OUT("reply", 5)) == 0);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL,
	    channel_send_reply(request, OUT("again", 5)) == -1);
	channel_message_free(request);
}

static void
event_handler(struct channel *channel, struct channel_message *event,
    void *argument)
{
	struct exchange_state *state;

	(void)channel;
	state = argument;
	ATF_CHECK_EQ(CHANNEL_MESSAGE_EVENT, channel_message_kind(event));
	ATF_CHECK_EQ(0, channel_message_token(event));
	ATF_CHECK_EQ(5, channel_message_length(event));
	ATF_CHECK(memcmp(channel_message_data(event), "event", 5) == 0);
	if (channel_message_fd_count(event) == 1)
		state->taken_fd = channel_message_take_fd(event, 0);
	state->events++;
	channel_message_free(event);
}

static void
reorder_reply_handler(struct channel_request *request,
    struct channel_message *reply, int error, void *argument)
{
	struct reply_expectation *expectation;
	struct reorder_state *state;

	expectation = argument;
	state = expectation->state;
	if (error != 0) {
		state->errors++;
	} else {
		ATF_REQUIRE(reply != NULL);
		ATF_CHECK_EQ(expectation->length,
		    channel_message_length(reply));
		ATF_CHECK(memcmp(channel_message_data(reply),
		    expectation->payload, expectation->length) == 0);
		state->reply_order[state->replies++] = expectation->ordinal;
		channel_message_free(reply);
	}
	channel_request_release(request);
}

static void
reorder_request_handler(struct channel *channel,
    struct channel_message *request, void *argument)
{
	struct reorder_state *state;
	const char *data;

	(void)channel;
	state = argument;
	ATF_REQUIRE(state->requests < 2);
	ATF_CHECK_EQ(CHANNEL_MESSAGE_REQUEST,
	    channel_message_kind(request));
	data = channel_message_data(request);
	if (channel_message_length(request) == 3 &&
	    memcmp(data, "one", 3) == 0)
		state->held[0] = request;
	else if (channel_message_length(request) == 3 &&
	    memcmp(data, "two", 3) == 0)
		state->held[1] = request;
	else
		atf_tc_fail("unexpected request payload");
	state->requests++;
	if (state->requests != 2)
		return;

	/*
	 * A retained request keeps its channel alive and may be answered after
	 * the dispatch callback returns.  Deliberately reverse the replies.
	 */
	ATF_REQUIRE(state->held[0] != NULL);
	ATF_REQUIRE(state->held[1] != NULL);
	ATF_REQUIRE(channel_send_reply(state->held[1], OUT("second", 6)) ==
	    0);
	ATF_REQUIRE(channel_send_reply(state->held[0], OUT("first", 5)) ==
	    0);
	channel_message_free(state->held[1]);
	channel_message_free(state->held[0]);
	state->held[0] = state->held[1] = NULL;
}

static void
terminal_reply_handler(struct channel_request *request,
    struct channel_message *reply, int error, void *argument)
{
	struct terminal_state *state;

	state = argument;
	state->callbacks++;
	state->error = error;
	ATF_CHECK(reply == NULL);
	channel_request_release(request);
}

static void
destroying_reply_handler(struct channel_request *request,
    struct channel_message *reply, int error, void *argument)
{
	struct channel *channel;

	channel = argument;
	ATF_CHECK_EQ(0, error);
	ATF_REQUIRE(reply != NULL);
	channel_request_release(request);
	channel_destroy(channel);
	channel_message_free(reply);
}

ATF_TC(invalid_arguments);
ATF_TC_HEAD(invalid_arguments, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "libchannel rejects invalid handles, roles, and messages");
}
ATF_TC_BODY(invalid_arguments, tc)
{
	struct channel_options options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_CLIENT);
	struct channel_outgoing outgoing =
	    CHANNEL_OUTGOING_INITIALIZER("x", 1);
	struct channel *channel;
	int fd;

	(void)tc;
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, channel_create(-1, &options, &channel) == -1);
	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	errno = 0;
	ATF_CHECK(channel_create(fd, &options, &channel) == -1);
	close(fd);
	options.role = 0;
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, channel_create(0, &options, &channel) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL,
	    channel_send_event(NULL, OUT("x", 1)) == -1);
	outgoing.size = 0;
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL,
	    channel_send_event(NULL, &outgoing) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, channel_dispatch(NULL) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, channel_flush(NULL) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, channel_request_cancel(NULL) == -1);
}

ATF_TC(message_null_accessors);
ATF_TC_HEAD(message_null_accessors, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "message inspection has deterministic null-handle behavior");
}
ATF_TC_BODY(message_null_accessors, tc)
{
	(void)tc;
	ATF_CHECK_EQ(0, channel_message_kind(NULL));
	ATF_CHECK(channel_message_data(NULL) == NULL);
	ATF_CHECK_EQ(0, channel_message_length(NULL));
	ATF_CHECK_EQ(0, channel_message_token(NULL));
	ATF_CHECK(channel_message_sender(NULL) == NULL);
	ATF_CHECK_EQ(0, channel_message_fd_count(NULL));
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL,
	    channel_message_borrow_fd(NULL, 0) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL,
	    channel_message_take_fd(NULL, 0) == -1);
	channel_message_free(NULL);
	channel_request_release(NULL);
	channel_destroy(NULL);
}

ATF_TC_WITH_CLEANUP(request_reply_event_and_cancellation);
ATF_TC_HEAD(request_reply_event_and_cancellation, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "requests, replies, events, fd ownership, cancellation, duplicate responses, and stale replies are deterministic");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(request_reply_event_and_cancellation, tc)
{
	struct channel_options client_options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_CLIENT);
	struct channel_options provider_options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_PROVIDER);
	struct channel_outgoing outgoing =
	    CHANNEL_OUTGOING_INITIALIZER("event", 5);
	struct channel_request *pending;
	struct exchange_state state;
	struct channel *client, *provider;
	char byte;
	int ends[2], first, second;

	(void)tc;
	memset(&state, 0, sizeof(state));
	state.taken_fd = -1;
	capability_channel_pair(&first, &second);
	ATF_REQUIRE(channel_create(first, &client_options, &client) == 0);
	ATF_REQUIRE(channel_create(second, &provider_options, &provider) == 0);
	ATF_REQUIRE(channel_set_request_handler(provider, request_handler,
	    &state) == 0);
	ATF_REQUIRE(channel_set_event_handler(provider, event_handler,
	    &state) == 0);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL,
	    channel_send_request(provider, OUT("request", 7), reply_handler,
	    &state, &pending) == -1);
	outgoing.size = sizeof(outgoing) - 1;
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL,
	    channel_send_event(client, &outgoing) == -1);
	ATF_CHECK_EQ(0, channel_error(client));
	outgoing.size = sizeof(outgoing) + 32;
	ATF_REQUIRE(channel_send_event(client, &outgoing) == 0);
	ATF_CHECK_EQ(1, dispatch_wait(provider));
	ATF_CHECK_EQ(1, state.events);

	ATF_REQUIRE(channel_send_request(client, OUT("request", 7),
	    reply_handler, &state, &pending) == 0);
	ATF_CHECK_EQ(1, dispatch_wait(provider));
	ATF_CHECK_EQ(1, state.requests);
	ATF_CHECK_EQ(1, dispatch_wait(client));
	ATF_CHECK_EQ(1, state.replies);

	ATF_REQUIRE(pipe(ends) == 0);
	byte = 'x';
	ATF_REQUIRE(write(ends[1], &byte, 1) == 1);
	ATF_REQUIRE(channel_send_event(client,
	    OUT_FDS("event", 5, &ends[0], 1)) == 0);
	close(ends[0]);
	close(ends[1]);
	ATF_CHECK_EQ(1, dispatch_wait(provider));
	ATF_CHECK_EQ(2, state.events);
	ATF_REQUIRE(state.taken_fd >= 0);
	ATF_REQUIRE(read(state.taken_fd, &byte, 1) == 1);
	ATF_CHECK_EQ('x', byte);
	close(state.taken_fd);

	ATF_REQUIRE(channel_send_request(client, OUT("request", 7),
	    reply_handler, &state, &pending) == 0);
	ATF_REQUIRE(channel_request_cancel(pending) == 0);
	ATF_CHECK_EQ(1, state.canceled);
	ATF_CHECK_EQ(1, dispatch_wait(provider));
	ATF_CHECK_EQ(2, state.requests);
	/* The canceled request's late response is stale and silently drained. */
	ATF_CHECK_EQ(1, dispatch_wait(client));
	ATF_CHECK_EQ(1, state.replies);
	ATF_CHECK_EQ(0, channel_wants_write(client));
	channel_destroy(provider);
	channel_destroy(client);
}
ATF_TC_CLEANUP(request_reply_event_and_cancellation, tc)
{
	(void)tc;
}

ATF_TC_WITH_CLEANUP(reordered_replies_and_retained_requests);
ATF_TC_HEAD(reordered_replies_and_retained_requests, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "tokens correlate reversed replies and retained provider requests remain valid after dispatch");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(reordered_replies_and_retained_requests, tc)
{
	struct channel_options client_options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_CLIENT);
	struct channel_options provider_options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_PROVIDER);
	struct reply_expectation first, second_reply;
	struct channel_request *request;
	struct reorder_state state;
	struct channel *client, *provider;
	int first_fd, second_fd;

	(void)tc;
	memset(&state, 0, sizeof(state));
	first.state = &state;
	first.payload = "first";
	first.length = 5;
	first.ordinal = 1;
	second_reply.state = &state;
	second_reply.payload = "second";
	second_reply.length = 6;
	second_reply.ordinal = 2;

	capability_channel_pair(&first_fd, &second_fd);
	ATF_REQUIRE(channel_create(first_fd, &client_options, &client) == 0);
	ATF_REQUIRE(channel_create(second_fd, &provider_options, &provider) ==
	    0);
	ATF_REQUIRE(channel_set_request_handler(provider,
	    reorder_request_handler, &state) == 0);

	ATF_REQUIRE(channel_send_request(client, OUT("one", 3),
	    reorder_reply_handler, &first, &request) == 0);
	channel_request_release(request);
	ATF_REQUIRE(channel_send_request(client, OUT("two", 3),
	    reorder_reply_handler, &second_reply, &request) == 0);
	while (state.requests < 2)
		ATF_CHECK(dispatch_wait(provider) > 0);
	ATF_CHECK_EQ(2, state.requests);
	while (state.replies < 2)
		ATF_CHECK(dispatch_wait(client) > 0);
	ATF_CHECK_EQ(2, state.replies);
	ATF_CHECK_EQ(2, state.reply_order[0]);
	ATF_CHECK_EQ(1, state.reply_order[1]);
	ATF_CHECK_EQ(0, state.errors);

	channel_destroy(provider);
	channel_destroy(client);
}
ATF_TC_CLEANUP(reordered_replies_and_retained_requests, tc)
{
	(void)tc;
}

ATF_TC_WITH_CLEANUP(peer_death_fails_outstanding_requests);
ATF_TC_HEAD(peer_death_fails_outstanding_requests, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "peer death becomes a terminal channel error and completes every outstanding request exactly once");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(peer_death_fails_outstanding_requests, tc)
{
	struct channel_options client_options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_CLIENT);
	struct channel_options provider_options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_PROVIDER);
	struct channel_request *request;
	struct terminal_state state;
	struct channel *client, *provider;
	int error, first, second;

	(void)tc;
	memset(&state, 0, sizeof(state));
	capability_channel_pair(&first, &second);
	ATF_REQUIRE(channel_create(first, &client_options, &client) == 0);
	ATF_REQUIRE(channel_create(second, &provider_options, &provider) == 0);
	ATF_REQUIRE(channel_send_request(client, OUT("pending", 7),
	    terminal_reply_handler, &state, &request) == 0);

	channel_destroy(provider);
	errno = 0;
	ATF_CHECK(dispatch_wait(client) == -1);
	error = errno;
	ATF_CHECK_MSG(error == ECONNRESET || error == EPIPE,
	    "unexpected peer-death error: %s", strerror(error));
	ATF_CHECK_EQ(1, state.callbacks);
	ATF_CHECK_EQ(error, state.error);
	errno = 0;
	ATF_CHECK_ERRNO(error, channel_error(client) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(error,
	    channel_send_event(client, OUT("late", 4)) == -1);
	ATF_CHECK_EQ(1, state.callbacks);
	channel_destroy(client);
}
ATF_TC_CLEANUP(peer_death_fails_outstanding_requests, tc)
{
	(void)tc;
}

ATF_TC_WITH_CLEANUP(client_death_notifies_provider);
ATF_TC_HEAD(client_death_notifies_provider, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "closing a client endpoint makes an idle provider endpoint terminal");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(client_death_notifies_provider, tc)
{
	struct channel_options client_options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_CLIENT);
	struct channel_options provider_options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_PROVIDER);
	struct channel *client, *provider;
	int error, first, second;

	(void)tc;
	capability_channel_pair(&first, &second);
	ATF_REQUIRE(channel_create(first, &client_options, &client) == 0);
	ATF_REQUIRE(channel_create(second, &provider_options, &provider) == 0);

	channel_destroy(client);
	errno = 0;
	ATF_CHECK(dispatch_wait(provider) == -1);
	error = errno;
	ATF_CHECK_MSG(error == ECONNRESET || error == EPIPE,
	    "unexpected client-death error: %s", strerror(error));
	errno = 0;
	ATF_CHECK_ERRNO(error, channel_error(provider) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(error,
	    channel_send_event(provider, OUT("late", 4)) == -1);
	channel_destroy(provider);
}
ATF_TC_CLEANUP(client_death_notifies_provider, tc)
{
	(void)tc;
}

ATF_TC_WITH_CLEANUP(fork_rejects_inherited_channels);
ATF_TC_HEAD(fork_rejects_inherited_channels, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "a child cannot use or close parent channel descriptor numbers");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(fork_rejects_inherited_channels, tc)
{
	struct channel_options client_options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_CLIENT);
	struct channel_options provider_options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_PROVIDER);
	struct channel *client, *provider;
	pid_t child;
	int first, second, status;

	(void)tc;
	capability_channel_pair(&first, &second);
	ATF_REQUIRE(channel_create(first, &client_options, &client) == 0);
	ATF_REQUIRE(channel_create(second, &provider_options, &provider) == 0);
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		errno = 0;
		if (channel_fd(client) != -1 || errno != ECHILD)
			_exit(1);
		errno = 0;
		if (channel_send_event(client, OUT("child", 5)) != -1 ||
		    errno != ECHILD)
			_exit(2);
		channel_abandon(client);
		channel_abandon(provider);
		_exit(0);
	}
	ATF_REQUIRE(waitpid(child, &status, 0) == child);
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK_EQ(0, WEXITSTATUS(status));
	ATF_REQUIRE(channel_send_event(client, OUT("parent", 6)) == 0);
	ATF_CHECK(dispatch_wait(provider) > 0);
	channel_destroy(provider);
	channel_destroy(client);
}
ATF_TC_CLEANUP(fork_rejects_inherited_channels, tc)
{
	(void)tc;
}

ATF_TC_WITH_CLEANUP(stale_reply_closes_descriptors);
ATF_TC_HEAD(stale_reply_closes_descriptors, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "unknown reply tokens are discarded and every attached descriptor is closed");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(stale_reply_closes_descriptors, tc)
{
	struct channel_options client_options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_CLIENT);
	struct channel_options provider_options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_PROVIDER);
	struct mac_capability_sendmsg_args send;
	struct channel *client, *provider;
	char byte;
	int ends[2], first, second;

	(void)tc;
	capability_channel_pair(&first, &second);
	ATF_REQUIRE(channel_create(first, &client_options, &client) == 0);
	ATF_REQUIRE(channel_create(second, &provider_options, &provider) == 0);
	ATF_REQUIRE(pipe(ends) == 0);
	memset(&send, 0, sizeof(send));
	send.payload = "stale";
	send.payload_len = 5;
	send.fds = &ends[1];
	send.nfds = 1;
	send.reply_token = UINT64_C(0xfedcba9876543210);
	ATF_REQUIRE(ioctl(channel_fd(provider), MAC_CAPABILITY_SENDMSG,
	    &send) == 0);
	close(ends[1]);

	ATF_CHECK_EQ(1, dispatch_wait(client));
	ATF_REQUIRE(fcntl(ends[0], F_SETFL, O_NONBLOCK) == 0);
	ATF_CHECK_EQ(0, read(ends[0], &byte, 1));
	close(ends[0]);
	channel_destroy(provider);
	channel_destroy(client);
}
ATF_TC_CLEANUP(stale_reply_closes_descriptors, tc)
{
	(void)tc;
}

ATF_TC_WITH_CLEANUP(queued_attachments_close_on_destroy);
ATF_TC_HEAD(queued_attachments_close_on_destroy, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "backpressured attachment duplicates are all closed with their channel");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(queued_attachments_close_on_destroy, tc)
{
	struct channel_options client_options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_CLIENT);
	struct channel_options provider_options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_PROVIDER);
	struct channel *client, *provider;
	char byte;
	unsigned sends;
	int ends[2], first, second;

	(void)tc;
	capability_channel_pair(&first, &second);
	ATF_REQUIRE(channel_create(first, &client_options, &client) == 0);
	ATF_REQUIRE(channel_create(second, &provider_options, &provider) == 0);
	ATF_REQUIRE(pipe(ends) == 0);
	for (sends = 0; sends < MAC_CAPABILITY_DEFAULT_QUEUE_DEPTH + 2;
	    sends++) {
		ATF_REQUIRE(channel_send_event(client,
		    OUT_FDS("fd", 2, &ends[1], 1)) == 0);
		if (channel_wants_write(client) == 1)
			break;
	}
	ATF_REQUIRE_MSG(channel_wants_write(client) == 1,
	    "kernel channel never applied backpressure after %u sends", sends);
	close(ends[1]);
	channel_destroy(client);
	channel_destroy(provider);
	ATF_REQUIRE(fcntl(ends[0], F_SETFL, O_NONBLOCK) == 0);
	ATF_CHECK_EQ(0, read(ends[0], &byte, 1));
	close(ends[0]);
}
ATF_TC_CLEANUP(queued_attachments_close_on_destroy, tc)
{
	(void)tc;
}

ATF_TC_WITH_CLEANUP(destroy_from_callback);
ATF_TC_HEAD(destroy_from_callback, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "destroying a channel from a reply callback is deferred until dispatch unwinds");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(destroy_from_callback, tc)
{
	struct channel_options client_options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_CLIENT);
	struct channel_options provider_options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_PROVIDER);
	struct exchange_state state;
	struct channel_request *request;
	struct channel *client, *provider;
	int first, second;

	(void)tc;
	memset(&state, 0, sizeof(state));
	capability_channel_pair(&first, &second);
	ATF_REQUIRE(channel_create(first, &client_options, &client) == 0);
	ATF_REQUIRE(channel_create(second, &provider_options, &provider) == 0);
	ATF_REQUIRE(channel_set_request_handler(provider, request_handler,
	    &state) == 0);
	ATF_REQUIRE(channel_send_request(client, OUT("request", 7),
	    destroying_reply_handler, client, &request) == 0);
	ATF_CHECK_EQ(1, dispatch_wait(provider));
	ATF_CHECK_EQ(1, dispatch_wait(client));
	channel_destroy(provider);
}
ATF_TC_CLEANUP(destroy_from_callback, tc)
{
	(void)tc;
}

/*
 * Capability channels are kqueue-only: poll(2)/select(2) must fail with
 * POLLNVAL rather than reporting a bogus always-ready result.  This guards the
 * kernel fo_poll behaviour that channel_wait's readiness contract depends on.
 */
ATF_TC_WITH_CLEANUP(poll_is_unsupported);
ATF_TC_HEAD(poll_is_unsupported, tc)
{
	atf_tc_set_md_var(tc, "descr", "poll(2) on a channel returns POLLNVAL");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(poll_is_unsupported, tc)
{
	struct pollfd pollfd;
	int first, second;

	(void)tc;
	capability_channel_pair(&first, &second);
	memset(&pollfd, 0, sizeof(pollfd));
	pollfd.fd = first;
	pollfd.events = POLLIN | POLLOUT;
	ATF_REQUIRE_MSG(poll(&pollfd, 1, 0) == 1, "poll: %s", strerror(errno));
	ATF_CHECK_EQ_MSG(POLLNVAL, pollfd.revents & POLLNVAL,
	    "expected POLLNVAL, got %#x", pollfd.revents);
	ATF_CHECK_EQ(0, pollfd.revents & (POLLIN | POLLOUT));
	(void)close(first);
	(void)close(second);
}
ATF_TC_CLEANUP(poll_is_unsupported, tc)
{
	(void)tc;
}

/*
 * channel_wait: times out when idle, reports CHANNEL_WAIT_READ once a peer
 * message is pending, and fails EBADF on a destroyed channel.
 */
ATF_TC_WITH_CLEANUP(channel_wait_readiness);
ATF_TC_HEAD(channel_wait_readiness, tc)
{
	atf_tc_set_md_var(tc, "descr", "channel_wait reports channel readiness");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(channel_wait_readiness, tc)
{
	struct channel_options client_options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_CLIENT);
	struct channel_options provider_options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
	struct exchange_state state;
	struct channel *client, *provider;
	int first, second;

	(void)tc;
	memset(&state, 0, sizeof(state));
	state.taken_fd = -1;
	capability_channel_pair(&first, &second);
	ATF_REQUIRE(channel_create(first, &client_options, &client) == 0);
	ATF_REQUIRE(channel_create(second, &provider_options, &provider) == 0);
	ATF_REQUIRE(channel_set_event_handler(provider, event_handler,
	    &state) == 0);

	/* Idle: no message pending, so a bounded wait times out (0). */
	ATF_CHECK_EQ(0, channel_wait(provider, 0, 100));

	/* After a send, the provider end becomes readable. */
	ATF_REQUIRE(channel_send_event(client, OUT("event", 5)) == 0);
	ATF_CHECK_EQ(CHANNEL_WAIT_READ,
	    channel_wait(provider, 0, 5000) & CHANNEL_WAIT_READ);
	ATF_CHECK(channel_dispatch(provider) >= 0);
	ATF_CHECK_EQ(1, state.events);

	channel_destroy(client);
	channel_destroy(provider);
}
ATF_TC_CLEANUP(channel_wait_readiness, tc)
{
	(void)tc;
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, invalid_arguments);
	ATF_TP_ADD_TC(tp, message_null_accessors);
	ATF_TP_ADD_TC(tp, poll_is_unsupported);
	ATF_TP_ADD_TC(tp, channel_wait_readiness);
	ATF_TP_ADD_TC(tp, request_reply_event_and_cancellation);
	ATF_TP_ADD_TC(tp, reordered_replies_and_retained_requests);
	ATF_TP_ADD_TC(tp, peer_death_fails_outstanding_requests);
	ATF_TP_ADD_TC(tp, client_death_notifies_provider);
	ATF_TP_ADD_TC(tp, fork_rejects_inherited_channels);
	ATF_TP_ADD_TC(tp, stale_reply_closes_descriptors);
	ATF_TP_ADD_TC(tp, queued_attachments_close_on_destroy);
	ATF_TP_ADD_TC(tp, destroy_from_callback);
	return (atf_no_error());
}
