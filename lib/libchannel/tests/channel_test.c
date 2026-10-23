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
#include <sys/time.h>

#include <dev/mac_capability/mac_capability_channel_proto.h>
#include <dev/mac_capability/mac_capability_ioctl.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>
#include <channel.h>
#include <pthread.h>

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
static volatile sig_atomic_t wait_signal_count;
static struct sigaction wait_ignore_signal;

static void
wait_alarm(int signo __unused)
{
	int saved_errno = errno;

	if (++wait_signal_count >= 100)
		(void)sigaction(SIGALRM, &wait_ignore_signal, NULL);
	errno = saved_errno;
}

ATF_TC(channel_wait_interrupted_deadline);
ATF_TC_HEAD(channel_wait_interrupted_deadline, tc)
{
	atf_tc_set_md_var(tc, "descr", "Signals cannot restart a bounded channel receive wait");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "timeout", "15");
}
ATF_TC_BODY(channel_wait_interrupted_deadline, tc)
{
	struct channel_options options = CHANNEL_OPTIONS_INITIALIZER(CHANNEL_ROLE_CLIENT);
	struct channel *client;
	struct sigaction action;
	struct itimerval timer;
	struct timespec before, after;
	int first, second, result;
	sig_atomic_t observed;

	capability_channel_pair(&first, &second);
	ATF_REQUIRE_EQ(0, channel_create(first, &options, &client));
	ATF_CHECK_EQ(0, channel_wait(client, 0, 0));
	memset(&wait_ignore_signal, 0, sizeof(wait_ignore_signal));
	wait_ignore_signal.sa_handler = SIG_IGN;
	sigemptyset(&wait_ignore_signal.sa_mask);
	memset(&action, 0, sizeof(action));
	action.sa_handler = wait_alarm;
	sigemptyset(&action.sa_mask);
	ATF_REQUIRE_EQ(0, sigaction(SIGALRM, &action, NULL));
	wait_signal_count = 0;
	memset(&timer, 0, sizeof(timer));
	timer.it_value.tv_usec = timer.it_interval.tv_usec = 2000;
	ATF_REQUIRE_EQ(0, setitimer(ITIMER_REAL, &timer, NULL));
	ATF_REQUIRE_EQ(0, clock_gettime(CLOCK_MONOTONIC, &before));
	result = channel_wait(client, 0, 20);
	ATF_REQUIRE_EQ(0, clock_gettime(CLOCK_MONOTONIC, &after));
	observed = wait_signal_count;
	/* This ATF case has its own process; discard any pending final alarm. */
	ATF_REQUIRE_EQ(0, sigaction(SIGALRM, &wait_ignore_signal, NULL));
	memset(&timer, 0, sizeof(timer));
	ATF_REQUIRE_EQ(0, setitimer(ITIMER_REAL, &timer, NULL));
	printf("CHANNEL_INTERRUPTED_WAIT signals=%d elapsed_ms=%.3f\n",
	    (int)observed, (after.tv_sec - before.tv_sec) * 1000.0 +
	    (after.tv_nsec - before.tv_nsec) / 1000000.0);
	ATF_CHECK_EQ(0, result);
	ATF_CHECK_MSG(observed > 0 && observed < 100,
	    "wait must expire while interruptions continue, observed=%d", (int)observed);
	channel_destroy(client);
	close(second);
}

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

/*
 * Allocation-failure injection.  The test is linked statically with
 * -Wl,--wrap=malloc,--wrap=calloc, so libchannel's own allocations pass
 * through these wrappers.  Arm them immediately before the call under test
 * and disarm immediately after: nothing else may allocate in between.
 */
void	*__real_malloc(size_t);
void	*__real_calloc(size_t, size_t);
void	*__wrap_malloc(size_t);
void	*__wrap_calloc(size_t, size_t);

static int	allocation_failure_after = -1;	/* -1: disarmed */
static bool	allocation_failed;

static bool
allocation_should_fail(void)
{

	if (allocation_failure_after < 0)
		return (false);
	if (allocation_failure_after-- == 0) {
		allocation_failed = true;
		return (true);
	}
	return (false);
}

void *
__wrap_malloc(size_t size)
{

	if (allocation_should_fail()) {
		errno = ENOMEM;
		return (NULL);
	}
	return (__real_malloc(size));
}

void *
__wrap_calloc(size_t count, size_t size)
{

	if (allocation_should_fail()) {
		errno = ENOMEM;
		return (NULL);
	}
	return (__real_calloc(count, size));
}

/* Fail the (after + 1)th allocation from now. */
static void
arm_allocation_failure(int after)
{

	allocation_failed = false;
	allocation_failure_after = after;
}

static bool
disarm_allocation_failure(void)
{

	allocation_failure_after = -1;
	return (allocation_failed);
}

static struct channel_stats
stats_of(struct channel *channel)
{
	struct channel_stats stats = CHANNEL_STATS_INITIALIZER;

	ATF_REQUIRE(channel_get_stats(channel, &stats) == 0);
	return (stats);
}

/*
 * Sequence-numbered events: the receiver checks arrival order and keeps
 * the first attached descriptor of each message.
 */
struct sequence_state {
	uint32_t	expected;
	unsigned	received;
	unsigned	out_of_order;
	unsigned	with_fds;
	int		last_fd;
	size_t		last_length;
	unsigned char	last_byte;
};

static void
sequence_event_handler(struct channel *channel, struct channel_message *event,
    void *argument)
{
	struct sequence_state *state = argument;
	uint32_t sequence;

	(void)channel;
	ATF_REQUIRE(channel_message_length(event) >= sizeof(sequence));
	memcpy(&sequence, channel_message_data(event), sizeof(sequence));
	if (sequence != state->expected)
		state->out_of_order++;
	state->expected = sequence + 1;
	state->received++;
	state->last_length = channel_message_length(event);
	state->last_byte = ((const unsigned char *)channel_message_data(event))
	    [state->last_length - 1];
	if (channel_message_fd_count(event) != 0) {
		state->with_fds++;
		if (state->last_fd >= 0)
			close(state->last_fd);
		state->last_fd = channel_message_take_fd(event, 0);
	}
	channel_message_free(event);
}

/* Send sequence-numbered events until the kernel refuses one. */
static unsigned
fill_until_blocked(struct channel *client, uint32_t *sequence)
{
	unsigned sends;

	for (sends = 0; sends < MAC_CAPABILITY_DEFAULT_QUEUE_DEPTH +
	    MAC_CAPABILITY_DEFAULT_TX_LIMIT + 2; sends++) {
		ATF_REQUIRE(channel_send_event(client,
		    OUT(sequence, sizeof(*sequence))) == 0);
		(*sequence)++;
		if (channel_wants_write(client) == 1)
			break;
	}
	ATF_REQUIRE_MSG(channel_wants_write(client) == 1,
	    "kernel channel never applied backpressure after %u sends", sends);
	return (sends + 1);
}

/* Flush the client and dispatch the provider until total events arrived. */
static void
drain_sequence(struct channel *client, struct channel *provider,
    struct sequence_state *state, unsigned total)
{
	unsigned rounds;
	int ready;

	for (rounds = 0; rounds < 10000 && state->received < total; rounds++) {
		ATF_REQUIRE(channel_flush(client) == 0);
		ready = channel_wait(provider, 0, 200);
		ATF_REQUIRE(ready >= 0);
		if (ready > 0)
			ATF_REQUIRE(channel_dispatch(provider) >= 0);
	}
	ATF_REQUIRE_EQ_MSG(total, state->received, "%u of %u events arrived",
	    state->received, total);
}

/*
 * Make room at the peer and flush until nothing is queued.  The kernel
 * takes the queue, closing moved descriptors, before any received
 * descriptor can reuse their numbers in this one-process test.
 */
static void
flush_making_room(struct channel *client, struct channel *provider)
{
	unsigned rounds;

	for (rounds = 0; rounds < 100 && channel_wants_write(client) == 1;
	    rounds++) {
		ATF_REQUIRE(dispatch_wait(provider) >= 0);
		ATF_REQUIRE(channel_flush(client) == 0);
	}
	ATF_REQUIRE_EQ(0, channel_wants_write(client));
}

ATF_TC_WITH_CLEANUP(direct_send_statistics);
ATF_TC_HEAD(direct_send_statistics, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "an idle channel sends from the caller's memory, visible through "
	    "channel_get_stats, and never queues");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(direct_send_statistics, tc)
{
	struct channel_options client_options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_CLIENT);
	struct channel_options provider_options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_PROVIDER);
	struct channel_stats stats = CHANNEL_STATS_INITIALIZER;
	struct channel_request *pending;
	struct exchange_state state;
	struct channel *client, *provider;
	int first, second;
	unsigned i;

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
	ATF_CHECK_ERRNO(EINVAL, channel_get_stats(NULL, &stats) == -1);
	stats.size = 0;
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, channel_get_stats(client, &stats) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, channel_get_stats(client, NULL) == -1);
	stats = stats_of(client);
	ATF_CHECK_EQ(0, stats.sent_direct);
	ATF_CHECK_EQ(0, stats.sent_queued);
	ATF_CHECK_EQ(0, stats.sent_flushed);
	ATF_CHECK_EQ(0, stats.pending_requests);
	ATF_CHECK_EQ(0, stats.queued_messages);

	for (i = 0; i < 16; i++) {
		ATF_REQUIRE(channel_send_event(client, OUT("event", 5)) == 0);
		ATF_REQUIRE(channel_send_request(client, OUT("request", 7),
		    reply_handler, &state, &pending) == 0);
		stats = stats_of(client);
		ATF_CHECK_EQ(2 * (i + 1), stats.sent_direct);
		ATF_CHECK_EQ(0, stats.sent_queued);
		ATF_CHECK_EQ(1, stats.pending_requests);
		ATF_CHECK_EQ(0, channel_wants_write(client));
		ATF_CHECK_EQ(2, dispatch_wait(provider));
		ATF_CHECK_EQ(1, dispatch_wait(client));
		stats = stats_of(client);
		ATF_CHECK_EQ(0, stats.pending_requests);
	}
	ATF_CHECK_EQ(16, state.events);
	ATF_CHECK_EQ(16, state.requests);
	ATF_CHECK_EQ(16, state.replies);
	/* The provider replied directly every time, too. */
	stats = stats_of(provider);
	ATF_CHECK_EQ(16, stats.sent_direct);
	ATF_CHECK_EQ(0, stats.sent_queued);
	ATF_CHECK_EQ(0, stats.sent_flushed);
	channel_destroy(client);
	channel_destroy(provider);
}
ATF_TC_CLEANUP(direct_send_statistics, tc)
{
	(void)tc;
}

ATF_TC_WITH_CLEANUP(direct_send_with_fds_and_specs);
ATF_TC_HEAD(direct_send_with_fds_and_specs, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "descriptors and expectations ride the direct path: narrowed, "
	    "locked and delivered in one call, the caller's copies intact");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(direct_send_with_fds_and_specs, tc)
{
	struct channel_options client_options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_CLIENT);
	struct channel_options provider_options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_PROVIDER);
	struct channel_fd_spec specs[2];
	struct channel_stats stats;
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
	memset(specs, 0, sizeof(specs));
	specs[0].type = CHANNEL_FD_TYPE_SOCKET;
	specs[0].rights = CHANNEL_FD_RIGHT_READ;
	specs[1].flags = CHANNEL_FD_LOCK_INHERIT;
	fds[0] = sv[0];
	fds[1] = ends[1];
	ATF_REQUIRE(channel_send_event(client,
	    OUT_SPEC("two", 3, fds, 2, specs, 0)) == 0);
	stats = stats_of(client);
	ATF_CHECK_EQ(1, stats.sent_direct);
	ATF_CHECK_EQ(0, stats.sent_queued);
	ATF_CHECK_EQ(0, channel_wants_write(client));
	/* Lent, not moved: both remain the caller's, rights untouched. */
	ATF_CHECK(fcntl(sv[0], F_GETFD) != -1);
	ATF_CHECK(fcntl(ends[1], F_GETFD) != -1);
	ATF_REQUIRE(cap_rights_get(sv[0], &rights) == 0);
	ATF_CHECK(cap_rights_is_set(&rights, CAP_WRITE));
	spec_receive(provider, &state);
	ATF_REQUIRE_EQ(2, state.nfds);
	ATF_REQUIRE(state.fds[0] >= 0 && state.fds[1] >= 0);
	ATF_REQUIRE(cap_rights_get(state.fds[0], &rights) == 0);
	cap_rights_init(&expected, CAP_READ, CAP_FSTAT);
	ATF_CHECK(cap_rights_contains(&expected, &rights));
	ATF_CHECK(cap_rights_contains(&rights, &expected));
	ATF_CHECK(!inheritance_locked(state.fds[0]));
	ATF_CHECK(inheritance_locked(state.fds[1]));
	ATF_CHECK_EQ(1, write(state.fds[1], "d", 1));
	ATF_CHECK_EQ(1, read(ends[0], &byte, 1));
	ATF_CHECK_EQ('d', byte);
	close(state.fds[0]);
	close(state.fds[1]);
	close(ends[0]);
	close(ends[1]);
	close(sv[0]);
	close(sv[1]);
	channel_destroy(client);
	channel_destroy(provider);
}
ATF_TC_CLEANUP(direct_send_with_fds_and_specs, tc)
{
	(void)tc;
}

ATF_TC_WITH_CLEANUP(backpressure_queues_in_order);
ATF_TC_HEAD(backpressure_queues_in_order, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "once the peer is full sends queue behind EAGAIN; later sends "
	    "queue behind them even when the kernel has room again, and every "
	    "message arrives in order");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(backpressure_queues_in_order, tc)
{
	struct channel_options client_options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_CLIENT);
	struct channel_options provider_options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_PROVIDER);
	struct sequence_state state;
	struct channel_stats stats;
	struct channel *client, *provider;
	uint32_t sequence;
	unsigned direct, sent, i;
	int first, second;

	(void)tc;
	memset(&state, 0, sizeof(state));
	state.last_fd = -1;
	capability_channel_pair(&first, &second);
	ATF_REQUIRE(channel_create(first, &client_options, &client) == 0);
	ATF_REQUIRE(channel_create(second, &provider_options, &provider) == 0);
	ATF_REQUIRE(channel_set_event_handler(provider, sequence_event_handler,
	    &state) == 0);
	sequence = 0;
	sent = fill_until_blocked(client, &sequence);
	stats = stats_of(client);
	direct = (unsigned)stats.sent_direct;
	ATF_CHECK_EQ(sent - 1, direct);
	ATF_CHECK_EQ(1, stats.sent_queued);
	ATF_CHECK_EQ(1, stats.queued_messages);
	ATF_CHECK_EQ(sizeof(sequence), stats.queued_bytes);
	/* Still blocked: more sends queue, none is sent directly. */
	for (i = 0; i < 5; i++) {
		ATF_REQUIRE(channel_send_event(client,
		    OUT(&sequence, sizeof(sequence))) == 0);
		sequence++;
	}
	sent += 5;
	stats = stats_of(client);
	ATF_CHECK_EQ(direct, stats.sent_direct);
	ATF_CHECK_EQ(6, stats.sent_queued);
	ATF_CHECK_EQ(6, stats.queued_messages);
	ATF_CHECK_EQ(6 * sizeof(sequence), stats.queued_bytes);
	/*
	 * Make room in the kernel without flushing: a new send must still
	 * queue behind the waiting messages, never overtake them.
	 */
	ATF_REQUIRE(dispatch_wait(provider) > 0);
	ATF_REQUIRE(dispatch_wait(provider) > 0);
	ATF_REQUIRE(state.received >= 2);
	ATF_REQUIRE(channel_send_event(client,
	    OUT(&sequence, sizeof(sequence))) == 0);
	sequence++;
	sent++;
	stats = stats_of(client);
	ATF_CHECK_EQ(direct, stats.sent_direct);
	ATF_CHECK_EQ(7, stats.sent_queued);
	ATF_CHECK_EQ(1, channel_wants_write(client));

	drain_sequence(client, provider, &state, sent);
	ATF_CHECK_EQ(0, state.out_of_order);
	ATF_CHECK_EQ(sequence, state.expected);
	ATF_CHECK_EQ(0, channel_wants_write(client));
	stats = stats_of(client);
	ATF_CHECK_EQ(7, stats.sent_flushed);
	ATF_CHECK_EQ(0, stats.queued_messages);
	ATF_CHECK_EQ(0, stats.queued_bytes);
	ATF_CHECK_EQ(direct, stats.sent_direct);
	/* Drained: the direct path resumes. */
	ATF_REQUIRE(channel_send_event(client,
	    OUT(&sequence, sizeof(sequence))) == 0);
	sequence++;
	sent++;
	stats = stats_of(client);
	ATF_CHECK_EQ(direct + 1, stats.sent_direct);
	ATF_CHECK_EQ(7, stats.sent_queued);
	drain_sequence(client, provider, &state, sent);
	ATF_CHECK_EQ(0, state.out_of_order);
	ATF_CHECK_EQ(0, channel_error(client));
	channel_destroy(client);
	channel_destroy(provider);
}
ATF_TC_CLEANUP(backpressure_queues_in_order, tc)
{
	(void)tc;
}

ATF_TC_WITH_CLEANUP(move_semantics_on_both_paths);
ATF_TC_HEAD(move_semantics_on_both_paths, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "CHANNEL_SEND_MOVE closes the caller's descriptor on acceptance, "
	    "sent or queued, and leaves it open on every failure");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(move_semantics_on_both_paths, tc)
{
	struct channel_options client_options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_CLIENT);
	struct channel_options provider_options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_PROVIDER);
	struct channel_fd_spec spec;
	struct sequence_state state;
	struct channel_stats stats;
	struct channel *client, *provider;
	uint32_t sequence;
	unsigned sent;
	int ends[2], moved[2], first, second;
	char byte;

	(void)tc;
	memset(&state, 0, sizeof(state));
	state.last_fd = -1;
	client_options.max_queued_messages = 2;
	capability_channel_pair(&first, &second);
	ATF_REQUIRE(channel_create(first, &client_options, &client) == 0);
	ATF_REQUIRE(channel_create(second, &provider_options, &provider) == 0);
	ATF_REQUIRE(channel_set_event_handler(provider, sequence_event_handler,
	    &state) == 0);
	sequence = 0;

	/* Direct path, failed expectation: still the caller's. */
	ATF_REQUIRE(pipe(ends) == 0);
	memset(&spec, 0, sizeof(spec));
	spec.type = CHANNEL_FD_TYPE_SOCKET;
	errno = 0;
	ATF_CHECK_ERRNO(EFTYPE, channel_send_event(client,
	    OUT_SPEC(&sequence, sizeof(sequence), &ends[1], 1, &spec,
	    CHANNEL_SEND_MOVE)) == -1);
	ATF_CHECK(fcntl(ends[1], F_GETFD) != -1);
	stats = stats_of(client);
	ATF_CHECK_EQ(0, stats.sent_direct);
	ATF_CHECK_EQ(0, stats.sent_queued);

	/* Direct path, accepted: gone from the caller's table. */
	ATF_REQUIRE(channel_send_event(client,
	    OUT_SPEC(&sequence, sizeof(sequence), &ends[1], 1, NULL,
	    CHANNEL_SEND_MOVE)) == 0);
	sequence++;
	errno = 0;
	ATF_CHECK_ERRNO(EBADF, fcntl(ends[1], F_GETFD) == -1);
	stats = stats_of(client);
	ATF_CHECK_EQ(1, stats.sent_direct);
	drain_sequence(client, provider, &state, 1);
	ATF_REQUIRE_EQ(1, state.with_fds);
	ATF_CHECK_EQ(1, write(state.last_fd, "a", 1));
	close(state.last_fd);
	state.last_fd = -1;
	ATF_CHECK_EQ(1, read(ends[0], &byte, 1));
	ATF_CHECK_EQ(0, read(ends[0], &byte, 1));	/* last writer gone */
	close(ends[0]);

	/* Queued path, accepted: adopted now, closed by the flush. */
	sent = 1 + fill_until_blocked(client, &sequence);
	ATF_REQUIRE(pipe(moved) == 0);
	ATF_REQUIRE(channel_send_event(client,
	    OUT_SPEC(&sequence, sizeof(sequence), &moved[1], 1, NULL,
	    CHANNEL_SEND_MOVE)) == 0);
	sequence++;
	sent++;
	stats = stats_of(client);
	ATF_CHECK_EQ(2, stats.sent_queued);
	ATF_CHECK_EQ(1, stats.queued_fds);
	/* Adopted: the number is the library's until it is sent. */
	ATF_CHECK(fcntl(moved[1], F_GETFD) != -1);

	/* Queued path, failed expectation behind the queue: still ours. */
	ATF_REQUIRE(pipe(ends) == 0);
	spec.type = CHANNEL_FD_TYPE_SOCKET;
	errno = 0;
	ATF_CHECK_ERRNO(EFTYPE, channel_send_event(client,
	    OUT_SPEC(&sequence, sizeof(sequence), &ends[1], 1, &spec,
	    CHANNEL_SEND_MOVE)) == -1);
	ATF_CHECK(fcntl(ends[1], F_GETFD) != -1);
	/* Queued path, bounded queue full: still ours, moved or lent. */
	errno = 0;
	ATF_CHECK_ERRNO(ENOBUFS, channel_send_event(client,
	    OUT_SPEC(&sequence, sizeof(sequence), &ends[1], 1, NULL,
	    CHANNEL_SEND_MOVE)) == -1);
	ATF_CHECK(fcntl(ends[1], F_GETFD) != -1);
	errno = 0;
	ATF_CHECK_ERRNO(ENOBUFS, channel_send_event(client,
	    OUT_FDS(&sequence, sizeof(sequence), &ends[1], 1)) == -1);
	ATF_CHECK(fcntl(ends[1], F_GETFD) != -1);
	stats = stats_of(client);
	ATF_CHECK_EQ(2, stats.sent_queued);
	ATF_CHECK_EQ(2, stats.queued_messages);
	ATF_CHECK_EQ(1, stats.queued_fds);
	ATF_CHECK_EQ(0, channel_error(client));
	close(ends[0]);
	close(ends[1]);

	flush_making_room(client, provider);
	errno = 0;
	ATF_CHECK_ERRNO(EBADF, fcntl(moved[1], F_GETFD) == -1);
	drain_sequence(client, provider, &state, sent);
	ATF_CHECK_EQ(0, state.out_of_order);
	ATF_REQUIRE_EQ(2, state.with_fds);
	ATF_CHECK_EQ(1, write(state.last_fd, "b", 1));
	close(state.last_fd);
	state.last_fd = -1;
	ATF_CHECK_EQ(1, read(moved[0], &byte, 1));
	ATF_CHECK_EQ('b', byte);
	ATF_CHECK_EQ(0, read(moved[0], &byte, 1));
	close(moved[0]);
	stats = stats_of(client);
	ATF_CHECK_EQ(2, stats.sent_flushed);
	ATF_CHECK_EQ(0, stats.queued_fds);
	channel_destroy(client);
	channel_destroy(provider);
}
ATF_TC_CLEANUP(move_semantics_on_both_paths, tc)
{
	(void)tc;
}

/* A provider that answers through the reserve/commit interface. */
struct buffer_state {
	unsigned	requests;
	unsigned	replies;
	unsigned	errors;
	size_t		reply_length;
	unsigned char	reply_first;
	unsigned char	reply_last;
	size_t		request_length;
};

static void
buffer_request_handler(struct channel *channel,
    struct channel_message *request, void *argument)
{
	struct buffer_state *state = argument;
	struct channel_outgoing_buffer *buffer;
	unsigned char *data;
	size_t length, i;

	ATF_CHECK_EQ(CHANNEL_MESSAGE_REQUEST, channel_message_kind(request));
	state->requests++;
	state->request_length = channel_message_length(request);
	/* Reply with twice the request, reserved generously, committed tight. */
	length = 2 * state->request_length;
	ATF_REQUIRE(channel_outgoing_reserve(channel, length + 100, 0,
	    &buffer) == 0);
	ATF_REQUIRE_EQ(length + 100, channel_outgoing_buffer_capacity(buffer));
	data = channel_outgoing_buffer_data(buffer);
	ATF_REQUIRE(data != NULL);
	for (i = 0; i < length; i++)
		data[i] = (unsigned char)(0x40 + i % 7);
	ATF_REQUIRE(channel_outgoing_commit_reply(buffer, request, length,
	    NULL, 0, NULL, 0) == 0);
	/* Answered: another reply is refused, even through a fresh buffer. */
	ATF_REQUIRE(channel_outgoing_reserve(channel, 8, 0, &buffer) == 0);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, channel_outgoing_commit_reply(buffer, request,
	    1, NULL, 0, NULL, 0) == -1);
	channel_outgoing_abort(buffer);
	channel_message_free(request);
}

static void
buffer_reply_handler(struct channel_request *request,
    struct channel_message *reply, int error, void *argument)
{
	struct buffer_state *state = argument;
	const unsigned char *data;

	if (error != 0) {
		state->errors++;
	} else {
		ATF_REQUIRE(reply != NULL);
		state->replies++;
		state->reply_length = channel_message_length(reply);
		data = channel_message_data(reply);
		state->reply_first = data[0];
		state->reply_last = data[state->reply_length - 1];
		channel_message_free(reply);
	}
	channel_request_release(request);
}

ATF_TC_WITH_CLEANUP(reserve_commit_abort_lifecycle);
ATF_TC_HEAD(reserve_commit_abort_lifecycle, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "a reserved send buffer is encoded in place and committed with "
	    "its actual length, aborted, or kept across a failed commit; "
	    "events, requests and replies all go through it");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(reserve_commit_abort_lifecycle, tc)
{
	struct channel_options client_options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_CLIENT);
	struct channel_options provider_options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_PROVIDER);
	struct channel_outgoing_buffer *buffer, *other;
	struct channel_request *pending, *refused;
	struct sequence_state events;
	struct buffer_state state;
	struct channel_stats stats;
	struct channel *client, *provider;
	unsigned char *data;
	uint32_t sequence;
	int ends[2], first, second;
	size_t i;

	(void)tc;
	memset(&state, 0, sizeof(state));
	memset(&events, 0, sizeof(events));
	events.last_fd = -1;
	capability_channel_pair(&first, &second);
	ATF_REQUIRE(channel_create(first, &client_options, &client) == 0);
	ATF_REQUIRE(channel_create(second, &provider_options, &provider) == 0);
	ATF_REQUIRE(channel_set_request_handler(provider,
	    buffer_request_handler, &state) == 0);
	ATF_REQUIRE(channel_set_event_handler(provider, sequence_event_handler,
	    &events) == 0);

	/* Reservation limits. */
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, channel_outgoing_reserve(NULL, 8, 0,
	    &buffer) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, channel_outgoing_reserve(client, 8, 0,
	    NULL) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, channel_outgoing_reserve(client, 0, 0,
	    &buffer) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, channel_outgoing_reserve(client,
	    MAC_CAPABILITY_MAX_MSG + 1, 0, &buffer) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, channel_outgoing_reserve(client, 8,
	    MAC_CAPABILITY_MAX_FDS + 1, &buffer) == -1);
	ATF_CHECK(buffer == NULL);
	ATF_CHECK(channel_outgoing_buffer_data(NULL) == NULL);
	ATF_CHECK_EQ(0, channel_outgoing_buffer_capacity(NULL));
	channel_outgoing_abort(NULL);

	/* Reserve and abort, twice over, with a second one outstanding. */
	ATF_REQUIRE(channel_outgoing_reserve(client, 1024, 2, &buffer) == 0);
	ATF_REQUIRE(channel_outgoing_reserve(client, MAC_CAPABILITY_MAX_MSG,
	    MAC_CAPABILITY_MAX_FDS, &other) == 0);
	ATF_CHECK(buffer != other);
	ATF_CHECK_EQ(1024, channel_outgoing_buffer_capacity(buffer));
	ATF_CHECK_EQ(MAC_CAPABILITY_MAX_MSG,
	    channel_outgoing_buffer_capacity(other));
	ATF_CHECK(channel_outgoing_buffer_data(buffer) != NULL);
	ATF_CHECK(channel_outgoing_buffer_data(other) != NULL);
	memset(channel_outgoing_buffer_data(other), 0xff,
	    MAC_CAPABILITY_MAX_MSG);
	channel_outgoing_abort(other);
	channel_outgoing_abort(buffer);
	stats = stats_of(client);
	ATF_CHECK_EQ(0, stats.sent_direct);
	ATF_CHECK_EQ(0, stats.sent_queued);

	/* Commit fewer bytes than reserved: exactly those arrive. */
	ATF_REQUIRE(channel_outgoing_reserve(client, 4096, 0, &buffer) == 0);
	data = channel_outgoing_buffer_data(buffer);
	ATF_REQUIRE(data != NULL);
	sequence = 0;
	memcpy(data, &sequence, sizeof(sequence));
	for (i = sizeof(sequence); i < 4096; i++)
		data[i] = (unsigned char)i;
	data[99] = 0xee;
	ATF_REQUIRE(channel_outgoing_commit_event(buffer, 100, NULL, 0, NULL,
	    0) == 0);
	buffer = NULL;
	stats = stats_of(client);
	ATF_CHECK_EQ(1, stats.sent_direct);
	ATF_CHECK_EQ(0, stats.sent_queued);
	drain_sequence(client, provider, &events, 1);
	ATF_CHECK_EQ(100, events.last_length);
	ATF_CHECK_EQ(0xee, events.last_byte);

	/* Rejected commits leave the buffer, and its contents, in place. */
	ATF_REQUIRE(channel_outgoing_reserve(client, 64, 0, &buffer) == 0);
	data = channel_outgoing_buffer_data(buffer);
	sequence = 1;
	memcpy(data, &sequence, sizeof(sequence));
	memset(data + sizeof(sequence), 0x5a, 64 - sizeof(sequence));
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, channel_outgoing_commit_event(buffer, 0, NULL,
	    0, NULL, 0) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, channel_outgoing_commit_event(buffer, 65, NULL,
	    0, NULL, 0) == -1);
	ATF_REQUIRE(pipe(ends) == 0);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, channel_outgoing_commit_event(buffer, 64,
	    &ends[1], 1, NULL, 0) == -1);	/* no descriptor was reserved */
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, channel_outgoing_commit_event(buffer, 64, NULL,
	    0, NULL, 0x80) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, channel_outgoing_commit_request(buffer, 64,
	    NULL, 0, NULL, 0, NULL, &state, &pending) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, channel_outgoing_commit_request(buffer, 64,
	    NULL, 0, NULL, 0, buffer_reply_handler, &state, NULL) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, channel_outgoing_commit_reply(buffer, NULL, 64,
	    NULL, 0, NULL, 0) == -1);
	ATF_CHECK(fcntl(ends[1], F_GETFD) != -1);
	ATF_CHECK_EQ(64, channel_outgoing_buffer_capacity(buffer));
	ATF_CHECK(channel_outgoing_buffer_data(buffer) == data);
	ATF_CHECK_EQ(0x5a, data[63]);
	stats = stats_of(client);
	ATF_CHECK_EQ(1, stats.sent_direct);
	ATF_CHECK_EQ(0, stats.pending_requests);
	ATF_REQUIRE(channel_outgoing_commit_event(buffer, 64, NULL, 0, NULL,
	    0) == 0);
	drain_sequence(client, provider, &events, 2);
	ATF_CHECK_EQ(64, events.last_length);
	ATF_CHECK_EQ(0x5a, events.last_byte);
	ATF_CHECK_EQ(0, events.out_of_order);

	/* A provider cannot commit a request; a client cannot reply. */
	ATF_REQUIRE(channel_outgoing_reserve(provider, 8, 0, &buffer) == 0);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, channel_outgoing_commit_request(buffer, 8,
	    NULL, 0, NULL, 0, buffer_reply_handler, &state, &pending) == -1);
	channel_outgoing_abort(buffer);

	/* Request and reply, both through buffers, matched by token. */
	for (i = 1; i <= 8; i++) {
		ATF_REQUIRE(channel_outgoing_reserve(client, 512, 0,
		    &buffer) == 0);
		data = channel_outgoing_buffer_data(buffer);
		memset(data, (int)i, 512);
		pending = NULL;
		ATF_REQUIRE(channel_outgoing_commit_request(buffer, 7 * i,
		    NULL, 0, NULL, 0, buffer_reply_handler, &state,
		    &pending) == 0);
		ATF_REQUIRE(pending != NULL);
		ATF_CHECK_EQ(EINPROGRESS, channel_request_status(pending));
		stats = stats_of(client);
		ATF_CHECK_EQ(1, stats.pending_requests);
		ATF_CHECK_EQ(0, stats.sent_queued);
		ATF_CHECK_EQ(1, dispatch_wait(provider));
		ATF_CHECK_EQ(7 * i, state.request_length);
		ATF_CHECK_EQ(1, dispatch_wait(client));
		ATF_CHECK_EQ(i, state.replies);
		ATF_CHECK_EQ(14 * i, state.reply_length);
		ATF_CHECK_EQ(0x40, state.reply_first);
		ATF_CHECK_EQ(0x40 + (14 * i - 1) % 7, state.reply_last);
		stats = stats_of(client);
		ATF_CHECK_EQ(0, stats.pending_requests);
	}
	ATF_CHECK_EQ(8, state.requests);
	ATF_CHECK_EQ(0, state.errors);
	stats = stats_of(provider);
	ATF_CHECK_EQ(8, stats.sent_direct);
	ATF_CHECK_EQ(0, stats.sent_queued);

	/* A pending-request limit refuses the commit; the buffer stays. */
	client_options.max_pending_requests = 1;
	close(ends[0]);
	close(ends[1]);
	channel_destroy(client);
	channel_destroy(provider);
	capability_channel_pair(&first, &second);
	ATF_REQUIRE(channel_create(first, &client_options, &client) == 0);
	ATF_REQUIRE(channel_create(second, &provider_options, &provider) == 0);
	ATF_REQUIRE(channel_outgoing_reserve(client, 8, 0, &buffer) == 0);
	memset(channel_outgoing_buffer_data(buffer), 1, 8);
	ATF_REQUIRE(channel_outgoing_commit_request(buffer, 8, NULL, 0, NULL,
	    0, buffer_reply_handler, &state, &pending) == 0);
	ATF_REQUIRE(channel_outgoing_reserve(client, 8, 0, &buffer) == 0);
	memset(channel_outgoing_buffer_data(buffer), 2, 8);
	errno = 0;
	ATF_CHECK_ERRNO(ENOBUFS, channel_outgoing_commit_request(buffer, 8,
	    NULL, 0, NULL, 0, buffer_reply_handler, &state, &refused) == -1);
	ATF_CHECK(refused == NULL);
	ATF_CHECK_EQ(8, channel_outgoing_buffer_capacity(buffer));
	ATF_CHECK_EQ(2, ((unsigned char *)channel_outgoing_buffer_data(
	    buffer))[7]);
	/* Still fine as an event. */
	ATF_REQUIRE(channel_outgoing_commit_event(buffer, 8, NULL, 0, NULL,
	    0) == 0);
	ATF_REQUIRE(channel_request_cancel(pending) == 0);
	ATF_CHECK_EQ(1, state.errors);

	/* Commit after destroy fails; abort after destroy is harmless. */
	ATF_REQUIRE(channel_outgoing_reserve(client, 16, 1, &buffer) == 0);
	ATF_REQUIRE(channel_outgoing_reserve(client, 16, 0, &other) == 0);
	channel_destroy(client);
	errno = 0;
	ATF_CHECK_ERRNO(ECANCELED, channel_outgoing_commit_event(buffer, 16,
	    NULL, 0, NULL, 0) == -1);
	ATF_CHECK(channel_outgoing_buffer_data(buffer) != NULL);
	channel_outgoing_abort(buffer);
	channel_outgoing_abort(other);
	channel_destroy(provider);
}
ATF_TC_CLEANUP(reserve_commit_abort_lifecycle, tc)
{
	(void)tc;
}

ATF_TC_WITH_CLEANUP(reserve_commit_under_backpressure);
ATF_TC_HEAD(reserve_commit_under_backpressure, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "a committed buffer becomes the queue entry without copying: "
	    "descriptors lent or moved, limits, and a failed commit kept");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(reserve_commit_under_backpressure, tc)
{
	struct channel_options client_options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_CLIENT);
	struct channel_options provider_options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_PROVIDER);
	struct channel_outgoing_buffer *buffer;
	struct channel_fd_spec spec;
	struct sequence_state events;
	struct buffer_state state;
	struct channel_stats stats;
	struct channel_request *pending;
	struct channel *client, *provider;
	unsigned char *data;
	uint32_t sequence;
	unsigned sent;
	int ends[2], moved[2], first, second;
	char byte;

	(void)tc;
	memset(&state, 0, sizeof(state));
	memset(&events, 0, sizeof(events));
	events.last_fd = -1;
	client_options.max_queued_messages = 4;
	capability_channel_pair(&first, &second);
	ATF_REQUIRE(channel_create(first, &client_options, &client) == 0);
	ATF_REQUIRE(channel_create(second, &provider_options, &provider) == 0);
	ATF_REQUIRE(channel_set_request_handler(provider,
	    buffer_request_handler, &state) == 0);
	ATF_REQUIRE(channel_set_event_handler(provider, sequence_event_handler,
	    &events) == 0);
	sequence = 0;
	sent = fill_until_blocked(client, &sequence);
	stats = stats_of(client);
	ATF_CHECK_EQ(1, stats.sent_queued);

	/* Lent descriptor, queued: a locked duplicate travels, ours stays. */
	ATF_REQUIRE(pipe(ends) == 0);
	ATF_REQUIRE(channel_outgoing_reserve(client, 300, 1, &buffer) == 0);
	data = channel_outgoing_buffer_data(buffer);
	memcpy(data, &sequence, sizeof(sequence));
	memset(data + sizeof(sequence), 0x11, 300 - sizeof(sequence));
	data[199] = 0x22;
	memset(&spec, 0, sizeof(spec));
	spec.flags = CHANNEL_FD_LOCK_INHERIT;
	ATF_REQUIRE(channel_outgoing_commit_event(buffer, 200, &ends[1], 1,
	    &spec, 0) == 0);
	sequence++;
	sent++;
	ATF_CHECK(fcntl(ends[1], F_GETFD) != -1);
	stats = stats_of(client);
	ATF_CHECK_EQ(2, stats.sent_queued);
	ATF_CHECK_EQ(2, stats.queued_messages);
	ATF_CHECK_EQ(1, stats.queued_fds);
	ATF_CHECK_EQ(sizeof(sequence) + 200, stats.queued_bytes);

	/* Moved descriptor, queued: adopted. */
	ATF_REQUIRE(pipe(moved) == 0);
	ATF_REQUIRE(channel_outgoing_reserve(client, 8, 1, &buffer) == 0);
	memcpy(channel_outgoing_buffer_data(buffer), &sequence,
	    sizeof(sequence));
	ATF_REQUIRE(channel_outgoing_commit_event(buffer, 8, &moved[1], 1,
	    NULL, CHANNEL_SEND_MOVE) == 0);
	sequence++;
	sent++;
	ATF_CHECK(fcntl(moved[1], F_GETFD) != -1);

	/* A request behind the queue: registered now, answered after flush. */
	ATF_REQUIRE(channel_outgoing_reserve(client, 21, 0, &buffer) == 0);
	memset(channel_outgoing_buffer_data(buffer), 7, 21);
	ATF_REQUIRE(channel_outgoing_commit_request(buffer, 21, NULL, 0, NULL,
	    0, buffer_reply_handler, &state, &pending) == 0);
	ATF_CHECK_EQ(EINPROGRESS, channel_request_status(pending));
	stats = stats_of(client);
	ATF_CHECK_EQ(4, stats.sent_queued);
	ATF_CHECK_EQ(4, stats.queued_messages);
	ATF_CHECK_EQ(1, stats.pending_requests);

	/* The bounded queue is full: the commit fails, the buffer stays. */
	ATF_REQUIRE(channel_outgoing_reserve(client, 8, 1, &buffer) == 0);
	data = channel_outgoing_buffer_data(buffer);
	memcpy(data, &sequence, sizeof(sequence));
	errno = 0;
	ATF_CHECK_ERRNO(ENOBUFS, channel_outgoing_commit_event(buffer, 8,
	    &ends[1], 1, NULL, CHANNEL_SEND_MOVE) == -1);
	ATF_CHECK(fcntl(ends[1], F_GETFD) != -1);
	/* A failed expectation behind the queue, likewise. */
	spec.type = CHANNEL_FD_TYPE_SOCKET;
	spec.flags = 0;
	errno = 0;
	ATF_CHECK_ERRNO(EFTYPE, channel_outgoing_commit_event(buffer, 8,
	    &ends[1], 1, &spec, CHANNEL_SEND_MOVE) == -1);
	ATF_CHECK(fcntl(ends[1], F_GETFD) != -1);
	ATF_CHECK_EQ(8, channel_outgoing_buffer_capacity(buffer));
	ATF_CHECK(channel_outgoing_buffer_data(buffer) == data);
	stats = stats_of(client);
	ATF_CHECK_EQ(4, stats.sent_queued);
	ATF_CHECK_EQ(0, channel_error(client));

	/* Flush everything; then the kept buffer goes directly. */
	flush_making_room(client, provider);
	errno = 0;
	ATF_CHECK_ERRNO(EBADF, fcntl(moved[1], F_GETFD) == -1);
	ATF_CHECK(fcntl(ends[1], F_GETFD) != -1);
	drain_sequence(client, provider, &events, sent);
	ATF_CHECK_EQ(0, events.out_of_order);
	ATF_CHECK_EQ(1, dispatch_wait(client));
	ATF_CHECK_EQ(1, state.replies);
	ATF_CHECK_EQ(42, state.reply_length);
	ATF_CHECK_EQ(21, state.request_length);
	ATF_CHECK_EQ(0, channel_wants_write(client));
	stats = stats_of(client);
	ATF_CHECK_EQ(4, stats.sent_flushed);
	ATF_CHECK_EQ(0, stats.queued_messages);
	ATF_CHECK_EQ(0, stats.queued_fds);
	ATF_CHECK_EQ(0, stats.pending_requests);
	ATF_REQUIRE_EQ(2, events.with_fds);
	/* The last descriptor seen is the moved pipe. */
	ATF_CHECK_EQ(1, write(events.last_fd, "m", 1));
	close(events.last_fd);
	events.last_fd = -1;
	ATF_CHECK_EQ(1, read(moved[0], &byte, 1));
	ATF_CHECK_EQ('m', byte);
	ATF_CHECK_EQ(0, read(moved[0], &byte, 1));
	close(moved[0]);
	ATF_REQUIRE(channel_outgoing_commit_event(buffer, 8, &ends[1], 1, NULL,
	    CHANNEL_SEND_MOVE) == 0);
	sent++;
	errno = 0;
	ATF_CHECK_ERRNO(EBADF, fcntl(ends[1], F_GETFD) == -1);
	stats = stats_of(client);
	ATF_CHECK_EQ(4, stats.sent_queued);
	drain_sequence(client, provider, &events, sent);
	ATF_CHECK_EQ(0, events.out_of_order);
	ATF_CHECK_EQ(3, events.with_fds);
	close(events.last_fd);
	close(ends[0]);
	channel_destroy(client);
	channel_destroy(provider);
}
ATF_TC_CLEANUP(reserve_commit_under_backpressure, tc)
{
	(void)tc;
}

ATF_TC_WITH_CLEANUP(allocation_failures_leave_state_intact);
ATF_TC_HEAD(allocation_failures_leave_state_intact, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "a failed allocation in reserve, queueing or request registration "
	    "reports ENOMEM, changes no accounting and keeps the caller's "
	    "descriptors");
	atf_tc_set_md_var(tc, "require.user", "root");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(allocation_failures_leave_state_intact, tc)
{
	struct channel_options client_options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_CLIENT);
	struct channel_options provider_options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_PROVIDER);
	struct channel_outgoing_buffer *buffer;
	struct channel_request *pending;
	struct sequence_state events;
	struct buffer_state state;
	struct channel_stats stats, before;
	struct channel *client, *provider;
	uint32_t sequence;
	unsigned sent;
	int ends[2], first, second, result;

	(void)tc;
	memset(&state, 0, sizeof(state));
	memset(&events, 0, sizeof(events));
	events.last_fd = -1;
	capability_channel_pair(&first, &second);
	ATF_REQUIRE(channel_create(first, &client_options, &client) == 0);
	ATF_REQUIRE(channel_create(second, &provider_options, &provider) == 0);
	ATF_REQUIRE(channel_set_request_handler(provider,
	    buffer_request_handler, &state) == 0);
	ATF_REQUIRE(channel_set_event_handler(provider, sequence_event_handler,
	    &events) == 0);

	/* A fresh channel has no spare block: reserve allocates. */
	arm_allocation_failure(0);
	result = channel_outgoing_reserve(client, 64, 1, &buffer);
	ATF_CHECK(disarm_allocation_failure());
	ATF_CHECK_ERRNO(ENOMEM, result == -1);
	ATF_CHECK(buffer == NULL);
	ATF_REQUIRE(channel_outgoing_reserve(client, 64, 1, &buffer) == 0);
	channel_outgoing_abort(buffer);

	/* Nor a spare request: registration allocates and fails cleanly. */
	arm_allocation_failure(0);
	result = channel_send_request(client, OUT("request", 7),
	    buffer_reply_handler, &state, &pending);
	ATF_CHECK(disarm_allocation_failure());
	ATF_CHECK_ERRNO(ENOMEM, result == -1);
	ATF_CHECK(pending == NULL);
	stats = stats_of(client);
	ATF_CHECK_EQ(0, stats.pending_requests);
	ATF_CHECK_EQ(0, stats.sent_direct);
	ATF_CHECK_EQ(0, channel_error(client));
	ATF_REQUIRE(channel_send_request(client, OUT("request", 7),
	    buffer_reply_handler, &state, &pending) == 0);
	ATF_CHECK_EQ(1, dispatch_wait(provider));
	ATF_CHECK_EQ(1, dispatch_wait(client));
	ATF_CHECK_EQ(1, state.replies);

	/*
	 * Queue a message so the spare block is in use; the next queued
	 * message needs a fresh block.
	 */
	sequence = 0;
	sent = fill_until_blocked(client, &sequence);
	before = stats_of(client);
	ATF_CHECK_EQ(1, before.sent_queued);
	ATF_REQUIRE(pipe(ends) == 0);
	arm_allocation_failure(0);
	result = channel_send_event(client, OUT_FDS(&sequence,
	    sizeof(sequence), &ends[1], 1));
	ATF_CHECK(disarm_allocation_failure());
	ATF_CHECK_ERRNO(ENOMEM, result == -1);
	ATF_CHECK(fcntl(ends[1], F_GETFD) != -1);
	arm_allocation_failure(0);
	result = channel_send_event(client, OUT_SPEC(&sequence,
	    sizeof(sequence), &ends[1], 1, NULL, CHANNEL_SEND_MOVE));
	ATF_CHECK(disarm_allocation_failure());
	ATF_CHECK_ERRNO(ENOMEM, result == -1);
	ATF_CHECK(fcntl(ends[1], F_GETFD) != -1);
	stats = stats_of(client);
	ATF_CHECK_EQ(before.sent_queued, stats.sent_queued);
	ATF_CHECK_EQ(before.queued_messages, stats.queued_messages);
	ATF_CHECK_EQ(before.queued_bytes, stats.queued_bytes);
	ATF_CHECK_EQ(0, stats.queued_fds);
	ATF_CHECK_EQ(0, channel_error(client));
	/*
	 * A queued request: the request itself comes from the spare kept by
	 * the exchange above, so the block is the first allocation.
	 */
	arm_allocation_failure(0);
	result = channel_send_request(client, OUT("request", 7),
	    buffer_reply_handler, &state, &pending);
	ATF_CHECK(disarm_allocation_failure());
	ATF_CHECK_ERRNO(ENOMEM, result == -1);
	ATF_CHECK(pending == NULL);
	stats = stats_of(client);
	ATF_CHECK_EQ(0, stats.pending_requests);
	ATF_CHECK_EQ(before.queued_messages, stats.queued_messages);
	/* Everything still works. */
	ATF_REQUIRE(channel_send_event(client, OUT_FDS(&sequence,
	    sizeof(sequence), &ends[1], 1)) == 0);
	sequence++;
	sent++;
	drain_sequence(client, provider, &events, sent);
	ATF_CHECK_EQ(0, events.out_of_order);
	ATF_CHECK_EQ(1, events.with_fds);
	close(events.last_fd);
	close(ends[0]);
	close(ends[1]);
	channel_destroy(client);
	channel_destroy(provider);
}
ATF_TC_CLEANUP(allocation_failures_leave_state_intact, tc)
{
	(void)tc;
}


/*
 * ---------------------------------------------------------------------
 * channel_call(3): MAC_CAPABILITY_CHANNEL_CALL and its fallback.
 *
 * The caller sleeps in the kernel, so the provider runs in a forked child.
 * Each request's first byte selects the provider's behaviour:
 *   e  echo: reply "re:" + payload
 *   c  reply with the number of requests served so far (ordering)
 *   d  reply after 300 ms
 *   v  send an event "evt", then reply
 *   f  reply with the request's descriptor count and a pipe write end
 *      attached (a byte written to it first)
 *   L  send an event carrying a pipe's read end, reply after 300 ms with
 *      the write end attached (late reply discard)
 *   b  reply with 8000 bytes
 *   Q  (event) flood the client with tx_limit events
 *   x  close the provider channel without replying
 *   t  MAC_CAPABILITY_TERMINATE the provider endpoint without replying
 * ---------------------------------------------------------------------
 */

struct call_provider {
	struct channel	*channel;
	unsigned	 served;
	uint32_t	 tx_limit;
	bool		 quit;
};

static void
call_provider_sleep(int ms)
{
	struct timespec ts;

	ts.tv_sec = ms / 1000;
	ts.tv_nsec = (long)(ms % 1000) * 1000000L;
	while (nanosleep(&ts, &ts) == -1 && errno == EINTR)
		;
}

static void
call_provider_request(struct channel *channel, struct channel_message *request,
    void *argument)
{
	struct call_provider *provider;
	const char *data;
	char reply[8000];
	size_t length;
	int ends[2], one;

	provider = argument;
	provider->served++;
	data = channel_message_data(request);
	length = channel_message_length(request);
	switch (length > 0 ? data[0] : 0) {
	case 'e':
		memcpy(reply, "re:", 3);
		memcpy(reply + 3, data, length);
		if (channel_send_reply(request, OUT(reply, length + 3)) != 0)
			_exit(10);
		break;
	case 'c':
		snprintf(reply, sizeof(reply), "%u", provider->served);
		if (channel_send_reply(request, OUT(reply, strlen(reply))) != 0)
			_exit(11);
		break;
	case 'd':
		call_provider_sleep(300);
		if (channel_send_reply(request, OUT("late", 4)) != 0)
			_exit(12);
		break;
	case 'v':
		if (channel_send_event(channel, OUT("evt", 3)) != 0)
			_exit(13);
		if (channel_send_reply(request, OUT("after", 5)) != 0)
			_exit(14);
		break;
	case 'f':
		/* The reply carries the read end of a pipe holding one byte. */
		if (pipe(ends) != 0 || write(ends[1], "p", 1) != 1)
			_exit(15);
		snprintf(reply, sizeof(reply), "%zu",
		    channel_message_fd_count(request));
		if (channel_send_reply(request, OUT_SPEC(reply, strlen(reply),
		    &ends[0], 1, NULL, CHANNEL_SEND_MOVE)) != 0)
			_exit(16);
		close(ends[1]);
		break;
	case 'L':
		if (pipe(ends) != 0)
			_exit(17);
		if (channel_send_event(channel, OUT_SPEC("rd", 2, &ends[0], 1,
		    NULL, CHANNEL_SEND_MOVE)) != 0)
			_exit(18);
		call_provider_sleep(300);
		if (channel_send_reply(request, OUT_SPEC("wr", 2, &ends[1], 1,
		    NULL, CHANNEL_SEND_MOVE)) != 0)
			_exit(19);
		break;
	case 'b':
		memset(reply, 'B', sizeof(reply));
		if (channel_send_reply(request, OUT(reply, sizeof(reply))) != 0)
			_exit(20);
		break;
	case 'x':
		provider->quit = true;
		break;
	case 't':
		one = ioctl(channel_fd(channel), MAC_CAPABILITY_TERMINATE, NULL);
		if (one != 0)
			_exit(21);
		provider->quit = true;
		break;
	default:
		_exit(22);
	}
	channel_message_free(request);
}

static void
call_provider_event(struct channel *channel, struct channel_message *event,
    void *argument)
{
	struct call_provider *provider;
	const char *data;
	uint32_t i;

	provider = argument;
	data = channel_message_data(event);
	if (channel_message_length(event) == 1 && data[0] == 'Q') {
		/* Fill the client's receive queue to the soft limit. */
		for (i = 0; i < provider->tx_limit; i++)
			if (channel_send_event(channel, OUT("flood", 5)) != 0)
				_exit(23);
		if (channel_wants_write(channel))
			_exit(24);	/* A direct send was refused. */
	}
	channel_message_free(event);
}

/* The child serves fd (several, for the concurrency test) until it dies. */
static pid_t
call_provider_fork(int *fds, size_t nfds, int *close_fds, size_t nclose)
{
	struct channel_options options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_PROVIDER);
	struct mac_capability_info_args info;
	struct call_provider providers[4];
	pid_t child;
	size_t i, alive;
	int ready;

	ATF_REQUIRE(nfds <= nitems(providers));
	child = fork();
	ATF_REQUIRE(child != -1);
	if (child != 0)
		return (child);
	for (i = 0; i < nclose; i++)
		close(close_fds[i]);
	memset(providers, 0, sizeof(providers));
	for (i = 0; i < nfds; i++) {
		memset(&info, 0, sizeof(info));
		if (ioctl(fds[i], MAC_CAPABILITY_GETINFO, &info) != 0)
			_exit(2);
		providers[i].tx_limit = info.tx_limit;
		if (channel_create(fds[i], &options, &providers[i].channel) != 0)
			_exit(3);
		channel_set_request_handler(providers[i].channel,
		    call_provider_request, &providers[i]);
		channel_set_event_handler(providers[i].channel,
		    call_provider_event, &providers[i]);
	}
	for (;;) {
		alive = 0;
		for (i = 0; i < nfds; i++) {
			if (providers[i].channel == NULL)
				continue;
			ready = channel_wait(providers[i].channel,
			    channel_wants_write(providers[i].channel),
			    nfds > 1 ? 5 : 1000);
			if (ready == -1 && errno != EINTR)
				_exit(4);
			if (channel_dispatch(providers[i].channel) == -1 ||
			    channel_flush(providers[i].channel) == -1 ||
			    providers[i].quit) {
				channel_destroy(providers[i].channel);
				providers[i].channel = NULL;
				continue;
			}
			alive++;
		}
		if (alive == 0)
			_exit(0);
	}
}

static void
call_provider_reap(pid_t child)
{
	int status;

	(void)kill(child, SIGKILL);
	ATF_REQUIRE(waitpid(child, &status, 0) == child);
}

/* Whether the kernel offers the one-call path on this descriptor. */
static bool
call_kernel_supported(int fd)
{
	struct mac_capability_info_args info;

	memset(&info, 0, sizeof(info));
	ATF_REQUIRE(ioctl(fd, MAC_CAPABILITY_GETINFO, &info) == 0);
	return ((info.features & MAC_CAPABILITY_INFO_F_CHANNEL_CALL) != 0);
}

struct call_client {
	struct channel	*channel;
	pid_t		 child;
	bool		 kernel;
	unsigned	 events;
	unsigned	 replies;
	int		 event_fd;
};

static void
call_client_event(struct channel *channel, struct channel_message *event,
    void *argument)
{
	struct call_client *client;

	(void)channel;
	client = argument;
	client->events++;
	if (channel_message_fd_count(event) == 1)
		client->event_fd = channel_message_take_fd(event, 0);
	channel_message_free(event);
}

static void
call_client_reply(struct channel_request *request,
    struct channel_message *reply, int error, void *argument)
{
	struct call_client *client;

	client = argument;
	ATF_CHECK_EQ(0, error);
	if (reply != NULL) {
		client->replies++;
		channel_message_free(reply);
	}
	channel_request_release(request);
}

static void
call_client_start(struct call_client *client)
{
	struct channel_options options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_CLIENT);
	int first, second;

	memset(client, 0, sizeof(*client));
	client->event_fd = -1;
	capability_channel_pair(&first, &second);
	client->kernel = call_kernel_supported(first);
	client->child = call_provider_fork(&second, 1, &first, 1);
	close(second);
	ATF_REQUIRE(channel_create(first, &options, &client->channel) == 0);
	channel_set_event_handler(client->channel, call_client_event, client);
}

static void
call_client_stop(struct call_client *client)
{

	if (client->channel != NULL)
		channel_destroy(client->channel);
	call_provider_reap(client->child);
}

static void
call_check_echo(struct call_client *client, const char *text)
{
	struct channel_message *reply;
	char expect[64];

	snprintf(expect, sizeof(expect), "re:%s", text);
	ATF_REQUIRE_MSG(channel_call(client->channel, OUT(text, strlen(text)),
	    &reply, 5000) == 0, "channel_call: %s", strerror(errno));
	ATF_REQUIRE(reply != NULL);
	ATF_CHECK_EQ(CHANNEL_MESSAGE_REPLY, channel_message_kind(reply));
	ATF_CHECK(channel_message_token(reply) != 0);
	ATF_CHECK_EQ(strlen(expect), channel_message_length(reply));
	ATF_CHECK(memcmp(channel_message_data(reply), expect, strlen(expect))
	    == 0);
	ATF_CHECK_EQ(0, channel_message_fd_count(reply));
	channel_message_free(reply);
}

ATF_TC_WITH_CLEANUP(call_round_trip);
ATF_TC_HEAD(call_round_trip, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "channel_call returns the matching reply with the metadata a "
	    "receive reports, and an event sent before the reply stays queued "
	    "for channel_dispatch when the kernel completes the call");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(call_round_trip, tc)
{
	struct call_client client;
	struct channel_message *reply;
	const struct channel_sender *sender;
	int i;

	(void)tc;
	call_client_start(&client);
	for (i = 0; i < 50; i++) {
		char text[16];

		snprintf(text, sizeof(text), "e%d", i);
		call_check_echo(&client, text);
	}
	ATF_REQUIRE(channel_call(client.channel, OUT("e", 1), &reply, 5000)
	    == 0);
	sender = channel_message_sender(reply);
	ATF_REQUIRE(sender != NULL);
	ATF_CHECK_EQ(getuid(), sender->uid);
	ATF_CHECK(sender->badge != 0);
	ATF_CHECK(channel_message_process(reply) != NULL);
	ATF_CHECK_EQ(client.child, channel_message_process(reply)->pid);
	channel_message_free(reply);

	/* Only the reply is taken; the event waits for dispatch. */
	ATF_REQUIRE(channel_call(client.channel, OUT("v", 1), &reply, 5000)
	    == 0);
	ATF_CHECK_EQ(5, channel_message_length(reply));
	ATF_CHECK(memcmp(channel_message_data(reply), "after", 5) == 0);
	channel_message_free(reply);
	if (client.kernel)
		ATF_CHECK_EQ(0, client.events);
	while (client.events == 0)
		ATF_REQUIRE(dispatch_wait(client.channel) >= 0);
	ATF_CHECK_EQ(1, client.events);
	ATF_CHECK_EQ(0, channel_error(client.channel));
	call_client_stop(&client);
}
ATF_TC_CLEANUP(call_round_trip, tc)
{
	(void)tc;
}

ATF_TC_WITH_CLEANUP(call_with_descriptors);
ATF_TC_HEAD(call_with_descriptors, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "channel_call moves descriptors with expectations in the request "
	    "and installs the reply's descriptors with kernel-reported info");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(call_with_descriptors, tc)
{
	struct call_client client;
	struct channel_message *reply;
	struct channel_fd_spec specs[2];
	struct channel_fd_info info;
	struct pollfd pfd;
	cap_rights_t rights;
	int a[2], b[2], sent[2], fd, i;
	char byte;

	(void)tc;
	call_client_start(&client);
	/*
	 * Descriptor numbers are reused by the reply's attachment, so a move
	 * is observed through the pipes themselves: pipe A's write end and
	 * pipe B's read end are moved, the other ends are kept.  Once the
	 * caller's descriptors are closed and the provider has freed its
	 * copies, A reports end of file and B has no reader left.
	 */
	ATF_REQUIRE(pipe(a) == 0 && pipe(b) == 0);
	ATF_REQUIRE(signal(SIGPIPE, SIG_IGN) != SIG_ERR);
	cap_rights_init(&rights, CAP_READ, CAP_FSTAT);
	ATF_REQUIRE(cap_rights_limit(b[0], &rights) == 0);
	sent[0] = b[0];
	sent[1] = a[1];
	memset(specs, 0, sizeof(specs));
	specs[1].type = CHANNEL_FD_TYPE_ANY;
	/* A failed expectation refuses the call before anything is sent. */
	specs[0].rights = CHANNEL_FD_RIGHT_WRITE;
	errno = 0;
	ATF_CHECK_ERRNO(ENOTCAPABLE, channel_call(client.channel,
	    OUT_SPEC("f", 1, sent, 2, specs, CHANNEL_SEND_MOVE), &reply, 5000)
	    == -1);
	ATF_CHECK(reply == NULL);
	ATF_CHECK(fcntl(b[0], F_GETFD) != -1);
	ATF_CHECK(fcntl(a[1], F_GETFD) != -1);
	ATF_CHECK_EQ(0, channel_error(client.channel));
	specs[0].rights = CHANNEL_FD_RIGHT_READ;
	ATF_REQUIRE_MSG(channel_call(client.channel,
	    OUT_SPEC("f", 1, sent, 2, specs, CHANNEL_SEND_MOVE), &reply, 5000)
	    == 0, "call with descriptors: %s", strerror(errno));
	/* Moved: the caller's descriptors are closed. */
	pfd.fd = a[0];
	pfd.events = POLLIN;
	for (i = 0; i < 40 && poll(&pfd, 1, 50) == 0; i++)
		;
	ATF_CHECK_MSG((pfd.revents & (POLLIN | POLLHUP)) != 0,
	    "pipe A still has a writer");
	if ((pfd.revents & (POLLIN | POLLHUP)) != 0)
		ATF_CHECK_EQ(0, read(a[0], &byte, 1));
	for (i = 0; i < 40 && write(b[1], "w", 1) == 1; i++)
		call_provider_sleep(50);
	errno = 0;
	ATF_CHECK_ERRNO(EPIPE, write(b[1], "w", 1) == -1);
	close(a[0]);
	close(b[1]);
	ATF_CHECK_EQ(1, channel_message_length(reply));
	ATF_CHECK(memcmp(channel_message_data(reply), "2", 1) == 0);
	ATF_REQUIRE_EQ(1, channel_message_fd_count(reply));
	if (channel_message_fd_info(reply, 0, &info) == 0) {
		ATF_CHECK_EQ(CHANNEL_FD_TYPE_OTHER, info.type);
		ATF_CHECK((info.rights & CHANNEL_FD_RIGHT_READ) != 0);
	} else
		ATF_CHECK_EQ(ENOTSUP, errno);
	fd = channel_message_take_fd(reply, 0);
	ATF_REQUIRE(fd >= 0);
	channel_message_free(reply);
	ATF_CHECK_EQ(1, read(fd, &byte, 1));
	ATF_CHECK_EQ('p', byte);
	close(fd);
	call_check_echo(&client, "e-after-fds");
	call_client_stop(&client);
}
ATF_TC_CLEANUP(call_with_descriptors, tc)
{
	(void)tc;
}

ATF_TC_WITH_CLEANUP(call_timeout_discards_late_reply);
ATF_TC_HEAD(call_timeout_discards_late_reply, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "a timed-out channel_call leaves the request sent, discards its "
	    "late reply closing the attached descriptors, keeps the channel "
	    "usable and never delivers the stale reply to a later call");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(call_timeout_discards_late_reply, tc)
{
	struct call_client client;
	struct channel_message *reply;
	struct pollfd pfd;
	struct timespec start, end;
	char byte;
	int ms;

	(void)tc;
	call_client_start(&client);
	ATF_REQUIRE(clock_gettime(CLOCK_MONOTONIC, &start) == 0);
	errno = 0;
	ATF_CHECK_ERRNO(ETIMEDOUT, channel_call(client.channel, OUT("L", 1),
	    &reply, 50) == -1);
	ATF_REQUIRE(clock_gettime(CLOCK_MONOTONIC, &end) == 0);
	ms = (int)((end.tv_sec - start.tv_sec) * 1000 +
	    (end.tv_nsec - start.tv_nsec) / 1000000);
	/* Well before the 5 s a lost reply would cost; loaded hosts jitter. */
	ATF_CHECK_MSG(ms >= 45 && ms < 2000, "timed out after %d ms", ms);
	ATF_CHECK(reply == NULL);
	ATF_CHECK_EQ(0, channel_error(client.channel));
	/* The event with the pipe's read end is still ours. */
	while (client.event_fd < 0)
		ATF_REQUIRE(dispatch_wait(client.channel) >= 0);
	/*
	 * The late reply carries the write end.  Discarded by the kernel (or
	 * by dispatch as stale), the only reference to it is dropped and the
	 * pipe reports end of file.
	 */
	pfd.fd = client.event_fd;
	pfd.events = POLLIN;
	for (int i = 0; i < 40 && poll(&pfd, 1, 50) == 0; i++)
		(void)channel_dispatch(client.channel);
	ATF_CHECK_MSG((pfd.revents & (POLLIN | POLLHUP)) != 0,
	    "the late reply's descriptor was not closed");
	ATF_CHECK_EQ(0, read(client.event_fd, &byte, 1));
	close(client.event_fd);
	/* The next call is matched by token, never by the stale reply. */
	call_check_echo(&client, "e-after-timeout");
	ATF_REQUIRE(channel_call(client.channel, OUT("c", 1), &reply, 5000)
	    == 0);
	ATF_CHECK_EQ(1, channel_message_length(reply));
	ATF_CHECK(memcmp(channel_message_data(reply), "3", 1) == 0);
	channel_message_free(reply);
	call_client_stop(&client);
}
ATF_TC_CLEANUP(call_timeout_discards_late_reply, tc)
{
	(void)tc;
}

ATF_TC_WITH_CLEANUP(call_peer_close_and_revocation);
ATF_TC_HEAD(call_peer_close_and_revocation, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "a peer that closes or terminates its endpoint while a call "
	    "waits completes the call with ECONNRESET and ends the channel");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(call_peer_close_and_revocation, tc)
{
	struct call_client client;
	struct channel_message *reply;
	const char *modes = "xt";
	size_t i;

	(void)tc;
	for (i = 0; i < strlen(modes); i++) {
		call_client_start(&client);
		call_check_echo(&client, "e");
		errno = 0;
		ATF_CHECK_ERRNO(ECONNRESET, channel_call(client.channel,
		    OUT(&modes[i], 1), &reply, 5000) == -1);
		ATF_CHECK(reply == NULL);
		errno = 0;
		ATF_CHECK_ERRNO(ECONNRESET, channel_error(client.channel) == -1);
		errno = 0;
		ATF_CHECK_ERRNO(ECONNRESET, channel_call(client.channel,
		    OUT("e", 1), &reply, 5000) == -1);
		call_client_stop(&client);
	}
}
ATF_TC_CLEANUP(call_peer_close_and_revocation, tc)
{
	(void)tc;
}

ATF_TC_WITH_CLEANUP(call_with_full_receive_queue);
ATF_TC_HEAD(call_with_full_receive_queue, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "a reply reaches a caller whose receive queue is at the soft "
	    "limit, and the queued events are then dispatched in order");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(call_with_full_receive_queue, tc)
{
	struct mac_capability_info_args info;
	struct call_client client;
	struct channel_message *reply;
	unsigned expected;

	(void)tc;
	call_client_start(&client);
	memset(&info, 0, sizeof(info));
	ATF_REQUIRE(ioctl(channel_fd(client.channel), MAC_CAPABILITY_GETINFO,
	    &info) == 0);
	expected = info.tx_limit;
	ATF_REQUIRE(channel_send_event(client.channel, OUT("Q", 1)) == 0);
	/* Let the flood land before calling into the full queue. */
	call_provider_sleep(300);
	ATF_REQUIRE_MSG(channel_call(client.channel, OUT("e", 1), &reply, 5000)
	    == 0, "call against a full queue: %s", strerror(errno));
	ATF_CHECK_EQ(4, channel_message_length(reply));
	ATF_CHECK(memcmp(channel_message_data(reply), "re:e", 4) == 0);
	channel_message_free(reply);
	if (client.kernel)
		ATF_CHECK_EQ(0, client.events);
	while (client.events < expected)
		ATF_REQUIRE(dispatch_wait(client.channel) >= 0);
	ATF_CHECK_EQ(expected, client.events);
	call_check_echo(&client, "e-drained");
	call_client_stop(&client);
}
ATF_TC_CLEANUP(call_with_full_receive_queue, tc)
{
	(void)tc;
}

ATF_TC_WITH_CLEANUP(call_interleaves_with_async_requests);
ATF_TC_HEAD(call_interleaves_with_async_requests, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "a call issued while an asynchronous request is outstanding "
	    "takes only its own reply; the other completes from dispatch");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(call_interleaves_with_async_requests, tc)
{
	struct call_client client;
	struct channel_request *request;
	struct channel_message *reply;

	(void)tc;
	call_client_start(&client);
	ATF_REQUIRE(channel_send_request(client.channel, OUT("c", 1),
	    call_client_reply, &client, &request) == 0);
	ATF_REQUIRE(channel_call(client.channel, OUT("c", 1), &reply, 5000)
	    == 0);
	/* Served second: the provider handles requests in order. */
	ATF_CHECK_EQ(1, channel_message_length(reply));
	ATF_CHECK(memcmp(channel_message_data(reply), "2", 1) == 0);
	channel_message_free(reply);
	if (client.kernel)
		ATF_CHECK_EQ(0, client.replies);
	while (client.replies == 0)
		ATF_REQUIRE(dispatch_wait(client.channel) >= 0);
	ATF_CHECK_EQ(1, client.replies);
	call_client_stop(&client);
}
ATF_TC_CLEANUP(call_interleaves_with_async_requests, tc)
{
	(void)tc;
}

struct call_thread {
	int		 fd;
	unsigned	 calls;
	int		 error;
};

static void *
call_thread_main(void *argument)
{
	struct channel_options options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_CLIENT);
	struct call_thread *thread;
	struct channel *channel;
	struct channel_message *reply;
	char text[32], expect[40];
	unsigned i;

	thread = argument;
	if (channel_create(thread->fd, &options, &channel) != 0) {
		thread->error = errno;
		return (NULL);
	}
	for (i = 0; i < 200; i++) {
		snprintf(text, sizeof(text), "e%p-%u", (void *)thread, i);
		snprintf(expect, sizeof(expect), "re:%s", text);
		if (channel_call(channel, OUT(text, strlen(text)), &reply,
		    5000) != 0) {
			thread->error = errno;
			break;
		}
		if (channel_message_length(reply) != strlen(expect) ||
		    memcmp(channel_message_data(reply), expect,
		    strlen(expect)) != 0) {
			thread->error = EPROTO;
			channel_message_free(reply);
			break;
		}
		channel_message_free(reply);
		thread->calls++;
	}
	channel_destroy(channel);
	return (NULL);
}

ATF_TC_WITH_CLEANUP(call_concurrent_channels);
ATF_TC_HEAD(call_concurrent_channels, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "callers on separate channels served by one provider process "
	    "each receive their own replies");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(call_concurrent_channels, tc)
{
	struct call_thread threads[3];
	pthread_t ids[3];
	int firsts[3], seconds[3];
	pid_t child;
	size_t i;

	(void)tc;
	for (i = 0; i < 3; i++)
		capability_channel_pair(&firsts[i], &seconds[i]);
	child = call_provider_fork(seconds, 3, firsts, 3);
	for (i = 0; i < 3; i++) {
		close(seconds[i]);
		memset(&threads[i], 0, sizeof(threads[i]));
		threads[i].fd = firsts[i];
		ATF_REQUIRE(pthread_create(&ids[i], NULL, call_thread_main,
		    &threads[i]) == 0);
	}
	for (i = 0; i < 3; i++) {
		ATF_REQUIRE(pthread_join(ids[i], NULL) == 0);
		ATF_CHECK_EQ_MSG(0, threads[i].error, "thread %zu: %s", i,
		    strerror(threads[i].error));
		ATF_CHECK_EQ(200, threads[i].calls);
	}
	call_provider_reap(child);
}
ATF_TC_CLEANUP(call_concurrent_channels, tc)
{
	(void)tc;
}

static volatile sig_atomic_t call_alarms;

static void
call_alarm(int signo __unused)
{

	call_alarms++;
}

ATF_TC_WITH_CLEANUP(call_survives_signal_and_large_reply);
ATF_TC_HEAD(call_survives_signal_and_large_reply, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "a signal during the kernel wait leaves the request outstanding "
	    "and its reply is still delivered; a reply larger than the "
	    "receive block arrives through the receive path");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(call_survives_signal_and_large_reply, tc)
{
	struct call_client client;
	struct channel_message *reply;
	struct sigaction sa, old;
	struct itimerval it;
	const char *data;
	size_t i;

	(void)tc;
	call_client_start(&client);
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = call_alarm;
	sa.sa_flags = 0;	/* No SA_RESTART: the ioctl returns EINTR. */
	ATF_REQUIRE(sigaction(SIGALRM, &sa, &old) == 0);
	memset(&it, 0, sizeof(it));
	it.it_value.tv_usec = 100000;
	call_alarms = 0;
	ATF_REQUIRE(setitimer(ITIMER_REAL, &it, NULL) == 0);
	ATF_REQUIRE_MSG(channel_call(client.channel, OUT("d", 1), &reply, 5000)
	    == 0, "interrupted call: %s", strerror(errno));
	ATF_CHECK_EQ(1, call_alarms);
	ATF_CHECK_EQ(4, channel_message_length(reply));
	ATF_CHECK(memcmp(channel_message_data(reply), "late", 4) == 0);
	channel_message_free(reply);
	ATF_REQUIRE(sigaction(SIGALRM, &old, NULL) == 0);
	/* A small reply sizes the block; the next reply does not fit. */
	call_check_echo(&client, "e");
	ATF_REQUIRE(channel_call(client.channel, OUT("b", 1), &reply, 5000)
	    == 0);
	ATF_REQUIRE_EQ(8000, channel_message_length(reply));
	data = channel_message_data(reply);
	for (i = 0; i < 8000; i++)
		if (data[i] != 'B')
			break;
	ATF_CHECK_EQ(8000, i);
	channel_message_free(reply);
	call_check_echo(&client, "e-after-large");
	call_client_stop(&client);
}
ATF_TC_CLEANUP(call_survives_signal_and_large_reply, tc)
{
	(void)tc;
}

ATF_TC_WITH_CLEANUP(call_falls_back_without_kernel_support);
ATF_TC_HEAD(call_falls_back_without_kernel_support, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "channel_call behaves identically through the send/wait/dispatch "
	    "path, forced by the environment and by an ioctl allowlist that "
	    "omits MAC_CAPABILITY_CHANNEL_CALL");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(call_falls_back_without_kernel_support, tc)
{
	static const cap_ioctl_t older[] = { MAC_CAPABILITY_GETINFO,
	    MAC_CAPABILITY_SENDMSG, MAC_CAPABILITY_SENDMSG_V2,
	    MAC_CAPABILITY_RECVMSG, MAC_CAPABILITY_RECVMSG_V2,
	    MAC_CAPABILITY_RECVMSG_V3, MAC_CAPABILITY_RECVMSG_V4 };
	struct channel_options options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_CLIENT);
	struct call_client client;
	struct channel_message *reply;
	int first, second, round;

	(void)tc;
	for (round = 0; round < 2; round++) {
		memset(&client, 0, sizeof(client));
		client.event_fd = -1;
		capability_channel_pair(&first, &second);
		if (round == 0)
			ATF_REQUIRE(setenv("LIBCHANNEL_NO_CHANNEL_CALL", "1", 1)
			    == 0);
		else
			ATF_REQUIRE(cap_ioctls_limit(first, older,
			    nitems(older)) == 0);
		client.child = call_provider_fork(&second, 1, &first, 1);
		close(second);
		ATF_REQUIRE(channel_create(first, &options, &client.channel)
		    == 0);
		channel_set_event_handler(client.channel, call_client_event,
		    &client);
		call_check_echo(&client, "e-fallback");
		/* The event arrives during the wait: dispatched already. */
		ATF_REQUIRE(channel_call(client.channel, OUT("v", 1), &reply,
		    5000) == 0);
		ATF_CHECK(memcmp(channel_message_data(reply), "after", 5) == 0);
		channel_message_free(reply);
		ATF_CHECK_EQ(1, client.events);
		errno = 0;
		ATF_CHECK_ERRNO(ETIMEDOUT, channel_call(client.channel,
		    OUT("d", 1), &reply, 50) == -1);
		ATF_CHECK_EQ(0, channel_error(client.channel));
		call_check_echo(&client, "e-after-fallback-timeout");
		ATF_REQUIRE(channel_call(client.channel, OUT("c", 1), &reply,
		    5000) == 0);
		ATF_CHECK(memcmp(channel_message_data(reply), "5", 1) == 0);
		channel_message_free(reply);
		if (round == 0)
			ATF_REQUIRE(unsetenv("LIBCHANNEL_NO_CHANNEL_CALL") == 0);
		call_client_stop(&client);
	}
}
ATF_TC_CLEANUP(call_falls_back_without_kernel_support, tc)
{
	(void)tc;
}

struct call_inline {
	struct channel_message	*reply;
	int			 error;
	unsigned		 completions;
};

static void
call_inline_handler(struct channel_request *request,
    struct channel_message *reply, int error, void *argument)
{
	struct call_inline *inline_state;

	(void)request;
	inline_state = argument;
	inline_state->completions++;
	inline_state->error = error;
	inline_state->reply = reply;
}

ATF_TC_WITH_CLEANUP(call_request_api);
ATF_TC_HEAD(call_request_api, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "channel_call_request completes before returning when the kernel "
	    "answers, reports its status, rejects invalid use and refuses "
	    "the provider role");
	atf_tc_set_md_var(tc, "require.kmods",
	    "mac_capability mac_capability_channel");
}
ATF_TC_BODY(call_request_api, tc)
{
	struct channel_options provider_options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_PROVIDER);
	struct call_client client;
	struct call_inline inline_state;
	struct channel_request *request;
	struct channel_message *reply;
	struct channel *provider;
	int first, second;

	(void)tc;
	call_client_start(&client);
	memset(&inline_state, 0, sizeof(inline_state));
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, channel_call_request(client.channel,
	    OUT("e", 1), NULL, &inline_state, &request, 1000) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, channel_call_request(client.channel,
	    OUT("e", 1), call_inline_handler, &inline_state, NULL, 1000) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, channel_call(client.channel, OUT("e", 1), NULL,
	    1000) == -1);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, channel_call(client.channel, OUT("e", 0),
	    &reply, 1000) == -1);
	ATF_REQUIRE(channel_call_request(client.channel, OUT("e", 1),
	    call_inline_handler, &inline_state, &request, 5000) == 0);
	ATF_REQUIRE(request != NULL);
	if (inline_state.completions == 0) {
		/* Sent the ordinary way: complete it from dispatch. */
		ATF_CHECK_EQ(EINPROGRESS, channel_request_status(request));
		while (inline_state.completions == 0)
			ATF_REQUIRE(dispatch_wait(client.channel) >= 0);
	} else
		ATF_CHECK(client.kernel);
	ATF_CHECK_EQ(1, inline_state.completions);
	ATF_CHECK_EQ(0, inline_state.error);
	ATF_CHECK_EQ(0, channel_request_status(request));
	ATF_REQUIRE(inline_state.reply != NULL);
	ATF_CHECK(memcmp(channel_message_data(inline_state.reply), "re:e", 4)
	    == 0);
	channel_message_free(inline_state.reply);
	channel_request_release(request);
	/* A timeout completes with ETIMEDOUT, leaving the channel healthy. */
	memset(&inline_state, 0, sizeof(inline_state));
	ATF_REQUIRE(channel_call_request(client.channel, OUT("d", 1),
	    call_inline_handler, &inline_state, &request, 50) == 0);
	if (inline_state.completions == 0) {
		ATF_CHECK(!client.kernel);
		ATF_CHECK_EQ(EINPROGRESS, channel_request_status(request));
		ATF_CHECK_EQ(0, channel_request_cancel(request));
		ATF_CHECK_EQ(ECANCELED, inline_state.error);
	} else {
		ATF_CHECK_EQ(ETIMEDOUT, inline_state.error);
		ATF_CHECK_EQ(ETIMEDOUT, channel_request_status(request));
	}
	ATF_CHECK(inline_state.reply == NULL);
	channel_request_release(request);
	ATF_CHECK_EQ(0, channel_error(client.channel));
	call_check_echo(&client, "e-after-request-api");
	call_client_stop(&client);

	capability_channel_pair(&first, &second);
	ATF_REQUIRE(channel_create(second, &provider_options, &provider) == 0);
	errno = 0;
	ATF_CHECK_ERRNO(EINVAL, channel_call(provider, OUT("e", 1), &reply,
	    1000) == -1);
	channel_destroy(provider);
	close(first);
}
ATF_TC_CLEANUP(call_request_api, tc)
{
	(void)tc;
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, channel_wait_interrupted_deadline);
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
	ATF_TP_ADD_TC(tp, direct_send_statistics);
	ATF_TP_ADD_TC(tp, direct_send_with_fds_and_specs);
	ATF_TP_ADD_TC(tp, backpressure_queues_in_order);
	ATF_TP_ADD_TC(tp, move_semantics_on_both_paths);
	ATF_TP_ADD_TC(tp, reserve_commit_abort_lifecycle);
	ATF_TP_ADD_TC(tp, reserve_commit_under_backpressure);
	ATF_TP_ADD_TC(tp, allocation_failures_leave_state_intact);
	ATF_TP_ADD_TC(tp, ioctl_allowlist_falls_back);
	ATF_TP_ADD_TC(tp, call_round_trip);
	ATF_TP_ADD_TC(tp, call_with_descriptors);
	ATF_TP_ADD_TC(tp, call_timeout_discards_late_reply);
	ATF_TP_ADD_TC(tp, call_peer_close_and_revocation);
	ATF_TP_ADD_TC(tp, call_with_full_receive_queue);
	ATF_TP_ADD_TC(tp, call_interleaves_with_async_requests);
	ATF_TP_ADD_TC(tp, call_concurrent_channels);
	ATF_TP_ADD_TC(tp, call_survives_signal_and_large_reply);
	ATF_TP_ADD_TC(tp, call_falls_back_without_kernel_support);
	ATF_TP_ADD_TC(tp, call_request_api);
	return (atf_no_error());
}
