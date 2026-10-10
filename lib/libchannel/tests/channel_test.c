/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/cap_process.h>
#include <sys/sysctl.h>
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



static void
capability_channel_pair(int *first, int *second)
{
	int pair[2], error;

	error = mac_capability_channel_create(pair);
	if (error == -1 && errno == ENOSYS)
		atf_tc_skip("kernel channel creation syscall unavailable");
	ATF_REQUIRE_MSG(error == 0, "channel pair: %s", strerror(errno));
	*first = pair[0];
	*second = pair[1];
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
	/*
	 * Sends flow through two kernel stages before the client sees
	 * backpressure: the sender's tx queue (csvc_tx_limit) drains into the
	 * provider's rx queue (csvc_queue_depth).  channel_wants_write only
	 * becomes true once SENDMSG returns EAGAIN, i.e. after both fill -- so
	 * drive enough sends to fill both, not just the receive depth.
	 */
	for (sends = 0; sends < MAC_CAPABILITY_DEFAULT_QUEUE_DEPTH +
	    MAC_CAPABILITY_DEFAULT_TX_LIMIT + 2; sends++) {
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

/*
 * Sender identity stamp: every received message carries the kernel-stamped
 * uid/gid/prison/nonce and (new) ABI of the sender.  Sending to a channel
 * pair inside this very process pins every field to a known value.
 */
struct sender_state {
	struct channel_sender sender;
	struct channel_process_identity process;
	bool seen;
};

static void
sender_event_handler(struct channel *channel, struct channel_message *message,
    void *cookie)
{
	struct sender_state *state = cookie;
	const struct channel_sender *sender;

	(void)channel;
	sender = channel_message_sender(message);
	ATF_REQUIRE(sender != NULL);
	state->sender = *sender;
	if (channel_message_process(message) != NULL)
		state->process = *channel_message_process(message);
	state->seen = true;
	channel_message_free(message);
}

ATF_TC_WITH_CLEANUP(sender_identity_stamp);
ATF_TC_HEAD(sender_identity_stamp, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "received messages carry the kernel-stamped sender uid/gid/nonce and ABI");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(sender_identity_stamp, tc)
{
	struct channel_options client_options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_CLIENT);
	struct channel_options provider_options =
	    CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_PROVIDER);
	struct sender_state state;
	struct channel *client, *provider;
	int first, second;

	(void)tc;
	memset(&state, 0, sizeof(state));
	capability_channel_pair(&first, &second);
	ATF_REQUIRE(channel_create(first, &client_options, &client) == 0);
	ATF_REQUIRE(channel_create(second, &provider_options, &provider) == 0);
	ATF_REQUIRE(channel_set_event_handler(provider, sender_event_handler,
	    &state) == 0);

	ATF_REQUIRE(channel_send_event(client, OUT("who", 3)) == 0);
	ATF_REQUIRE(dispatch_wait(provider) >= 0);
	ATF_REQUIRE(state.seen);

	if (feature_present("cap_process")) {
		struct mac_cap_process_info info;

		ATF_REQUIRE_EQ(0, cap_process(MAC_CAP_PROCESS_INFO, -1, 0, &info));
		ATF_CHECK_EQ(info.identity, state.process.identity);
		ATF_CHECK_EQ(info.responsible_identity,
		    state.process.responsible_identity);
		ATF_CHECK_EQ(getpid(), state.process.pid);
		ATF_CHECK_EQ(info.responsible_pid, state.process.responsible_pid);
	}

	ATF_CHECK_EQ(getuid(), state.sender.uid);
	ATF_CHECK_EQ(getgid(), state.sender.gid);
	ATF_CHECK(state.sender.nonce != 0);
	ATF_CHECK(state.sender.badge != 0);
	/*
	 * A kernel predating the ABI stamp reports CHANNEL_ABI_UNKNOWN for
	 * everything; the layout is otherwise identical, so flag rather than
	 * fail so the rest of the suite still validates on it.
	 */
	if (state.sender.abi == CHANNEL_ABI_UNKNOWN)
		atf_tc_expect_fail("running kernel does not stamp the sender ABI");
	ATF_CHECK_EQ(CHANNEL_ABI_NATIVE, state.sender.abi);

	channel_destroy(client);
	channel_destroy(provider);
}
ATF_TC_CLEANUP(sender_identity_stamp, tc)
{
	(void)tc;
}

/*
 * Receive blocks are sized from the previous message and grow before
 * dequeue when a message is larger.  Every size class must arrive intact,
 * including the maximum payload and attached descriptors, and retained
 * messages must not share storage with later receives.
 */
static const size_t receive_sizes[] = { 1, 600, MAC_CAPABILITY_MAX_MSG, 100,
    MAC_CAPABILITY_MAX_MSG, 5000, 512, 513 };
#define	RECEIVE_COUNT	(sizeof(receive_sizes) / sizeof(receive_sizes[0]))

struct receive_state {
	struct channel_message *held[RECEIVE_COUNT];
	unsigned count;
};

static unsigned char
receive_byte(size_t message, size_t offset)
{

	return ((unsigned char)(message * 31 + offset * 7 + 1));
}

static void
receive_event_handler(struct channel *channel, struct channel_message *event,
    void *argument)
{
	struct receive_state *state;

	(void)channel;
	state = argument;
	ATF_REQUIRE(state->count < RECEIVE_COUNT);
	state->held[state->count++] = event;
}

ATF_TC(receive_blocks_resize);
ATF_TC_HEAD(receive_blocks_resize, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "messages of every size class arrive intact and stay independent");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(receive_blocks_resize, tc)
{
	struct channel_options client_options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_CLIENT);
	struct channel_options provider_options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_PROVIDER);
	struct receive_state state;
	struct channel *client, *provider;
	unsigned char *payload;
	char byte;
	int first, second, pipefd[2], fd;
	size_t i, j;

	(void)tc;
	memset(&state, 0, sizeof(state));
	payload = malloc(MAC_CAPABILITY_MAX_MSG);
	ATF_REQUIRE(payload != NULL);
	ATF_REQUIRE(pipe(pipefd) == 0);
	capability_channel_pair(&first, &second);
	ATF_REQUIRE(channel_create(first, &client_options, &client) == 0);
	ATF_REQUIRE(channel_create(second, &provider_options, &provider) == 0);
	ATF_REQUIRE(channel_set_event_handler(client, receive_event_handler,
	    &state) == 0);
	for (i = 0; i < RECEIVE_COUNT; i++) {
		for (j = 0; j < receive_sizes[i]; j++)
			payload[j] = receive_byte(i, j);
		/* Attach a descriptor to the second maximum-size message. */
		if (i == 4)
			ATF_REQUIRE(channel_send_event(provider,
			    OUT_FDS(payload, receive_sizes[i], &pipefd[1], 1)) == 0);
		else
			ATF_REQUIRE(channel_send_event(provider,
			    OUT(payload, receive_sizes[i])) == 0);
		/* Receive each before sending the next: exercise every grow. */
		while (state.count <= i)
			ATF_REQUIRE(dispatch_wait(client) >= 0);
	}
	close(pipefd[1]);
	for (i = 0; i < RECEIVE_COUNT; i++) {
		const unsigned char *data = channel_message_data(state.held[i]);

		ATF_REQUIRE_EQ(receive_sizes[i],
		    channel_message_length(state.held[i]));
		for (j = 0; j < receive_sizes[i]; j++)
			if (data[j] != receive_byte(i, j))
				atf_tc_fail("message %zu byte %zu corrupted", i, j);
		ATF_CHECK_EQ(i == 4 ? 1 : 0,
		    channel_message_fd_count(state.held[i]));
	}
	fd = channel_message_take_fd(state.held[4], 0);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(write(fd, "x", 1) == 1);
	ATF_REQUIRE(read(pipefd[0], &byte, 1) == 1 && byte == 'x');
	close(fd);
	for (i = 0; i < RECEIVE_COUNT; i++)
		channel_message_free(state.held[i]);
	channel_destroy(client);
	channel_destroy(provider);
	close(pipefd[0]);
	free(payload);
}


struct prefetch_state {
	unsigned events;
};

static void
prefetch_event(struct channel *channel, struct channel_message *event,
    void *argument)
{
	struct prefetch_state *state = argument;

	(void)channel;
	ATF_CHECK_EQ(4, channel_message_length(event));
	state->events++;
	channel_message_free(event);
}

ATF_TC(wait_then_dispatch_once);
ATF_TC_HEAD(wait_then_dispatch_once, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "a message found by channel_wait is dispatched exactly once, and an "
	    "undispatched one is released (with its descriptors) on destroy");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(wait_then_dispatch_once, tc)
{
	struct channel_options client_options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_CLIENT);
	struct channel_options provider_options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_PROVIDER);
	struct prefetch_state state = { 0 };
	struct channel *client, *provider;
	int first, second, pipefd[2], flags;
	char byte;

	capability_channel_pair(&first, &second);
	ATF_REQUIRE(channel_create(first, &client_options, &client) == 0);
	ATF_REQUIRE(channel_create(second, &provider_options, &provider) == 0);
	ATF_REQUIRE(channel_set_event_handler(client, prefetch_event,
	    &state) == 0);

	ATF_REQUIRE(channel_send_event(provider, OUT("evt1", 4)) == 0);
	ATF_REQUIRE_EQ(CHANNEL_WAIT_READ, channel_wait(client, 0, 5000));
	/* A second wait before dispatch reports the held message again. */
	ATF_REQUIRE_EQ(CHANNEL_WAIT_READ, channel_wait(client, 0, 0));
	ATF_REQUIRE(channel_dispatch(client) >= 1);
	ATF_REQUIRE_EQ(1, state.events);
	ATF_REQUIRE(channel_dispatch(client) == 0);
	ATF_REQUIRE_EQ(1, state.events);
	/* Nothing queued: a bounded wait times out. */
	ATF_REQUIRE_EQ(0, channel_wait(client, 0, 50));

	/* A waited-for but undispatched message is freed by destroy. */
	ATF_REQUIRE(pipe(pipefd) == 0);
	ATF_REQUIRE(channel_send_event(provider,
	    OUT_FDS("evt2", 4, &pipefd[1], 1)) == 0);
	close(pipefd[1]);
	ATF_REQUIRE_EQ(CHANNEL_WAIT_READ, channel_wait(client, 0, 5000));
	channel_destroy(client);
	flags = fcntl(pipefd[0], F_GETFL);
	ATF_REQUIRE(fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK) == 0);
	ATF_REQUIRE_EQ_MSG(0, read(pipefd[0], &byte, 1),
	    "received descriptor survived destroy");
	ATF_REQUIRE_EQ(1, state.events);
	close(pipefd[0]);
	channel_destroy(provider);
}

#define	OUT_SPEC(_data, _length, _fds, _nfds, _specs, _flags)		\
	(&(struct channel_outgoing){					\
	    .size = sizeof(struct channel_outgoing),			\
	    .data = (_data),						\
	    .length = (_length),					\
	    .fds = (_fds),						\
	    .nfds = (_nfds),						\
	    .fd_specs = (_specs),					\
	    .flags = (_flags)						\
	})

struct spec_state {
	unsigned events;
	int fds[2];
	size_t nfds;
	bool have_info;
	struct channel_fd_info info[2];
};

static void
spec_event_handler(struct channel *channel, struct channel_message *event,
    void *argument)
{
	struct spec_state *state;
	size_t i;

	(void)channel;
	state = argument;
	state->events++;
	state->nfds = channel_message_fd_count(event);
	ATF_REQUIRE(state->nfds <= 2);
	state->have_info = true;
	for (i = 0; i < state->nfds; i++) {
		if (channel_message_fd_info(event, i, &state->info[i]) != 0) {
			/* Kernels without RECVMSG_V4 do not report. */
			ATF_CHECK_EQ(ENOTSUP, errno);
			state->have_info = false;
		}
		state->fds[i] = channel_message_take_fd(event, i);
	}
	channel_message_free(event);
}

static void
spec_receive(struct channel *provider, struct spec_state *state)
{
	unsigned before;

	before = state->events;
	while (state->events == before)
		ATF_REQUIRE(dispatch_wait(provider) >= 0);
}

static bool
inheritance_locked(int fd)
{
	bool exec_locked, fork_locked;

	exec_locked = cap_cloexec_limit(fd, CAP_CLOEXEC_UNLOCKED) == -1 &&
	    errno == ENOTCAPABLE;
	fork_locked = cap_clofork_limit(fd, CAP_CLOFORK_UNLOCKED) == -1 &&
	    errno == ENOTCAPABLE;
	ATF_CHECK_EQ(exec_locked, fork_locked);
	return (exec_locked && fork_locked);
}

ATF_TC_WITH_CLEANUP(descriptor_specs_move_and_lock);
ATF_TC_HEAD(descriptor_specs_move_and_lock, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "descriptor expectations, narrowing, move and inheritance locks "
	    "are applied in the send call, atomically");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(descriptor_specs_move_and_lock, tc)
{
	struct channel_options client_options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_CLIENT);
	struct channel_options provider_options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_PROVIDER);
	struct channel_fd_spec specs[2];
	struct spec_state state;
	struct channel *client, *provider;
	cap_rights_t rights, expected;
	int ends[2], sv[2], fds[2], first, second;
	char byte;

	(void)tc;
	memset(&state, 0, sizeof(state));
	capability_channel_pair(&first, &second);
	ATF_REQUIRE(channel_create(first, &client_options, &client) == 0);
	ATF_REQUIRE(channel_create(second, &provider_options, &provider) == 0);
	channel_set_event_handler(provider, spec_event_handler, &state);
	ATF_REQUIRE(pipe(ends) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

	/* A failed expectation leaves every descriptor with the caller. */
	memset(specs, 0, sizeof(specs));
	specs[1].type = CHANNEL_FD_TYPE_SOCKET;
	fds[0] = sv[0];
	fds[1] = ends[1];
	errno = 0;
	ATF_CHECK_ERRNO(EFTYPE, channel_send_event(client,
	    OUT_SPEC("x", 1, fds, 2, specs, CHANNEL_SEND_MOVE)) == -1);
	ATF_CHECK(fcntl(sv[0], F_GETFD) != -1);
	ATF_CHECK(fcntl(ends[1], F_GETFD) != -1);
	cap_rights_init(&rights, CAP_WRITE);
	ATF_REQUIRE(cap_rights_limit(ends[1], &rights) == 0);
	memset(specs, 0, sizeof(specs));
	specs[0].rights = CHANNEL_FD_RIGHT_READ;
	errno = 0;
	ATF_CHECK_ERRNO(ENOTCAPABLE, channel_send_event(client,
	    OUT_SPEC("x", 1, &ends[1], 1, specs, CHANNEL_SEND_MOVE)) == -1);
	ATF_CHECK(fcntl(ends[1], F_GETFD) != -1);
	specs[0].reserved = 1;
	specs[0].rights = 0;
	errno = 0;
	ATF_CHECK_ERRNO(EOPNOTSUPP, channel_send_event(client,
	    OUT_SPEC("x", 1, &ends[1], 1, specs, 0)) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, channel_send_event(client,
	    OUT_SPEC("x", 1, &ends[1], 1, NULL, 0x80)) == -1);

	/* Narrowing applies to the delivered copy only. */
	memset(specs, 0, sizeof(specs));
	specs[0].type = CHANNEL_FD_TYPE_SOCKET;
	specs[0].rights = CHANNEL_FD_RIGHT_READ;
	ATF_REQUIRE(channel_send_event(client,
	    OUT_SPEC("s", 1, &sv[0], 1, specs, 0)) == 0);
	spec_receive(provider, &state);
	ATF_REQUIRE_EQ(1, state.nfds);
	ATF_REQUIRE(state.fds[0] >= 0);
	ATF_REQUIRE(cap_rights_get(state.fds[0], &rights) == 0);
	cap_rights_init(&expected, CAP_READ, CAP_FSTAT);
	ATF_CHECK(cap_rights_contains(&expected, &rights));
	ATF_CHECK(cap_rights_contains(&rights, &expected));
	if (state.have_info) {
		ATF_CHECK_EQ(CHANNEL_FD_TYPE_SOCKET, state.info[0].type);
		ATF_CHECK_EQ(CHANNEL_FD_RIGHT_READ | CHANNEL_FD_RIGHT_FSTAT |
		    CHANNEL_FD_RIGHTS_EXACT, state.info[0].rights);
	}
	ATF_REQUIRE(cap_rights_get(sv[0], &rights) == 0);
	ATF_CHECK(cap_rights_is_set(&rights, CAP_WRITE));
	ATF_CHECK(!inheritance_locked(state.fds[0]));
	close(state.fds[0]);

	/* Move with locked inheritance: the sender's descriptor is gone. */
	memset(specs, 0, sizeof(specs));
	specs[0].flags = CHANNEL_FD_LOCK_INHERIT;
	ATF_REQUIRE(channel_send_event(client,
	    OUT_SPEC("m", 1, &ends[1], 1, specs, CHANNEL_SEND_MOVE)) == 0);
	errno = 0;
	ATF_CHECK_ERRNO(EBADF, fcntl(ends[1], F_GETFD) == -1);
	spec_receive(provider, &state);
	ATF_REQUIRE_EQ(1, state.nfds);
	ATF_CHECK(inheritance_locked(state.fds[0]));
	if (state.have_info) {
		ATF_CHECK_EQ(CHANNEL_FD_TYPE_OTHER, state.info[0].type);
		ATF_CHECK_EQ(CHANNEL_FD_RIGHT_WRITE | CHANNEL_FD_RIGHTS_EXACT,
		    state.info[0].rights);
	}
	ATF_CHECK_EQ(1, write(state.fds[0], "z", 1));
	close(state.fds[0]);
	ATF_CHECK_EQ(1, read(ends[0], &byte, 1));
	/* The moved copy was the last writer. */
	ATF_CHECK_EQ(0, read(ends[0], &byte, 1));

	/* Whole-message lock, channel type check, no specs. */
	capability_channel_pair(&fds[0], &fds[1]);
	memset(specs, 0, sizeof(specs));
	specs[0].type = CHANNEL_FD_TYPE_CHANNEL;
	ATF_REQUIRE(channel_send_event(client, OUT_SPEC("c", 1, &fds[0], 1,
	    specs, CHANNEL_SEND_MOVE | CHANNEL_SEND_LOCK_INHERIT)) == 0);
	spec_receive(provider, &state);
	ATF_REQUIRE_EQ(1, state.nfds);
	ATF_CHECK(inheritance_locked(state.fds[0]));
	if (state.have_info)
		ATF_CHECK_EQ(CHANNEL_FD_TYPE_CHANNEL, state.info[0].type);
	close(state.fds[0]);
	close(fds[1]);
	specs[0].rights = CHANNEL_FD_RIGHT_READ;
	errno = 0;
	ATF_CHECK_ERRNO(EOPNOTSUPP, channel_send_event(client,
	    OUT_SPEC("c", 1, &sv[1], 1, specs, 0)) == -1);

	close(ends[0]);
	close(sv[0]);
	close(sv[1]);
	channel_destroy(client);
	channel_destroy(provider);
}
ATF_TC_CLEANUP(descriptor_specs_move_and_lock, tc)
{
	(void)tc;
}

ATF_TC_WITH_CLEANUP(queued_move_delivers_once);
ATF_TC_HEAD(queued_move_delivers_once, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "a moved descriptor queued behind backpressure is adopted, "
	    "delivered once, and leaves no copy behind");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(queued_move_delivers_once, tc)
{
	struct channel_options client_options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_CLIENT);
	struct channel_options provider_options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_PROVIDER);
	struct channel_fd_spec spec;
	struct spec_state state;
	struct channel *client, *provider;
	unsigned sends, moved_events;
	int ends[2], first, second, received;
	char byte;

	(void)tc;
	memset(&state, 0, sizeof(state));
	capability_channel_pair(&first, &second);
	ATF_REQUIRE(channel_create(first, &client_options, &client) == 0);
	ATF_REQUIRE(channel_create(second, &provider_options, &provider) == 0);
	channel_set_event_handler(provider, spec_event_handler, &state);
	ATF_REQUIRE(pipe(ends) == 0);
	for (sends = 0; sends < MAC_CAPABILITY_DEFAULT_QUEUE_DEPTH +
	    MAC_CAPABILITY_DEFAULT_TX_LIMIT + 2; sends++) {
		ATF_REQUIRE(channel_send_event(client, OUT("q", 1)) == 0);
		if (channel_wants_write(client) == 1)
			break;
	}
	ATF_REQUIRE(channel_wants_write(client) == 1);
	memset(&spec, 0, sizeof(spec));
	spec.rights = CHANNEL_FD_RIGHT_WRITE;
	ATF_REQUIRE(channel_send_event(client,
	    OUT_SPEC("m", 1, &ends[1], 1, &spec, CHANNEL_SEND_MOVE)) == 0);
	/* Queued: the library owns the descriptor now. */
	received = -1;
	moved_events = 0;
	while (received == -1) {
		ATF_REQUIRE(dispatch_wait(provider) >= 0);
		ATF_REQUIRE(channel_flush(client) == 0);
		if (state.nfds == 1 && state.fds[0] >= 0) {
			received = state.fds[0];
			state.fds[0] = -1;
			moved_events++;
		}
		state.nfds = 0;
	}
	ATF_CHECK_EQ(1, moved_events);
	ATF_CHECK_EQ(0, channel_wants_write(client));
	ATF_CHECK_EQ(1, write(received, "y", 1));
	close(received);
	ATF_REQUIRE(fcntl(ends[0], F_SETFL, O_NONBLOCK) == 0);
	ATF_CHECK_EQ(1, read(ends[0], &byte, 1));
	ATF_CHECK_EQ(0, read(ends[0], &byte, 1));
	close(ends[0]);
	channel_destroy(client);
	channel_destroy(provider);
}
ATF_TC_CLEANUP(queued_move_delivers_once, tc)
{
	(void)tc;
}

ATF_TC_WITH_CLEANUP(outgoing_v1_layout);
ATF_TC_HEAD(outgoing_v1_layout, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "callers built against the original outgoing layout keep working");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(outgoing_v1_layout, tc)
{
	struct channel_options client_options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_CLIENT);
	struct channel_options provider_options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_PROVIDER);
	struct channel_outgoing old;
	struct spec_state state;
	struct channel *client, *provider;
	int ends[2], first, second;

	(void)tc;
	memset(&state, 0, sizeof(state));
	capability_channel_pair(&first, &second);
	ATF_REQUIRE(channel_create(first, &client_options, &client) == 0);
	ATF_REQUIRE(channel_create(second, &provider_options, &provider) == 0);
	channel_set_event_handler(provider, spec_event_handler, &state);
	ATF_REQUIRE(pipe(ends) == 0);
	/* Garbage past the v1 size must be ignored, not interpreted. */
	memset(&old, 0xa5, sizeof(old));
	old.size = CHANNEL_OUTGOING_SIZE_V1;
	old.data = "v";
	old.length = 1;
	old.fds = &ends[1];
	old.nfds = 1;
	ATF_REQUIRE(channel_send_event(client, &old) == 0);
	ATF_CHECK(fcntl(ends[1], F_GETFD) != -1);
	spec_receive(provider, &state);
	ATF_REQUIRE_EQ(1, state.nfds);
	close(state.fds[0]);
	old.size = CHANNEL_OUTGOING_SIZE_V1 - 1;
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, channel_send_event(client, &old) == -1);
	/* Between the two layouts is neither. */
	old.size = CHANNEL_OUTGOING_SIZE_V1 + 1;
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, channel_send_event(client, &old) == -1);
	close(ends[0]);
	close(ends[1]);
	channel_destroy(client);
	channel_destroy(provider);
}
ATF_TC_CLEANUP(outgoing_v1_layout, tc)
{
	(void)tc;
}

ATF_TC_WITH_CLEANUP(ioctl_allowlist_falls_back);
ATF_TC_HEAD(ioctl_allowlist_falls_back, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "a channel allowlisted to the older send and receive commands "
	    "still honors descriptor expectations and moves");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(ioctl_allowlist_falls_back, tc)
{
	static const cap_ioctl_t older[] = { MAC_CAPABILITY_GETINFO,
	    MAC_CAPABILITY_SENDMSG, MAC_CAPABILITY_RECVMSG,
	    MAC_CAPABILITY_RECVMSG_V2, MAC_CAPABILITY_RECVMSG_V3 };
	struct channel_options client_options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_CLIENT);
	struct channel_options provider_options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_PROVIDER);
	struct channel_fd_spec spec;
	struct spec_state state;
	struct channel *client, *provider;
	cap_rights_t rights;
	int ends[2], first, second;

	(void)tc;
	memset(&state, 0, sizeof(state));
	capability_channel_pair(&first, &second);
	ATF_REQUIRE(cap_ioctls_limit(first, older, nitems(older)) == 0);
	ATF_REQUIRE(cap_ioctls_limit(second, older, nitems(older)) == 0);
	ATF_REQUIRE(channel_create(first, &client_options, &client) == 0);
	ATF_REQUIRE(channel_create(second, &provider_options, &provider) == 0);
	channel_set_event_handler(provider, spec_event_handler, &state);
	ATF_REQUIRE(pipe(ends) == 0);
	cap_rights_init(&rights, CAP_WRITE, CAP_FSTAT);
	ATF_REQUIRE(cap_rights_limit(ends[1], &rights) == 0);
	memset(&spec, 0, sizeof(spec));
	spec.rights = CHANNEL_FD_RIGHT_READ;
	errno = 0;
	ATF_CHECK_ERRNO(ENOTCAPABLE, channel_send_event(client,
	    OUT_SPEC("a", 1, &ends[1], 1, &spec, CHANNEL_SEND_MOVE)) == -1);
	ATF_CHECK(fcntl(ends[1], F_GETFD) != -1);
	ATF_CHECK_EQ(0, channel_error(client));
	spec.rights = CHANNEL_FD_RIGHT_WRITE;
	spec.flags = CHANNEL_FD_LOCK_INHERIT;
	ATF_REQUIRE(channel_send_event(client,
	    OUT_SPEC("a", 1, &ends[1], 1, &spec, CHANNEL_SEND_MOVE)) == 0);
	errno = 0;
	ATF_CHECK_ERRNO(EBADF, fcntl(ends[1], F_GETFD) == -1);
	spec_receive(provider, &state);
	ATF_REQUIRE_EQ(1, state.nfds);
	ATF_CHECK(!state.have_info);
	ATF_REQUIRE(cap_rights_get(state.fds[0], &rights) == 0);
	ATF_CHECK(!cap_rights_is_set(&rights, CAP_FSTAT));
	ATF_CHECK(cap_rights_is_set(&rights, CAP_WRITE));
	ATF_CHECK(inheritance_locked(state.fds[0]));
	close(state.fds[0]);
	close(ends[0]);
	channel_destroy(client);
	channel_destroy(provider);
}
ATF_TC_CLEANUP(ioctl_allowlist_falls_back, tc)
{
	(void)tc;
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, invalid_arguments);
	ATF_TP_ADD_TC(tp, sender_identity_stamp);
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
	ATF_TP_ADD_TC(tp, receive_blocks_resize);
	ATF_TP_ADD_TC(tp, wait_then_dispatch_once);
	ATF_TP_ADD_TC(tp, descriptor_specs_move_and_lock);
	ATF_TP_ADD_TC(tp, queued_move_delivers_once);
	ATF_TP_ADD_TC(tp, outgoing_v1_layout);
	ATF_TP_ADD_TC(tp, ioctl_allowlist_falls_back);
	return (atf_no_error());
}
