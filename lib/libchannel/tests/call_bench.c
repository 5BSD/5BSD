/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * call_bench split|call CALLS [PAYLOAD]
 *
 * One client process issues CALLS synchronous requests against a forked
 * provider that echoes them, either the split way (channel_send_request,
 * then channel_wait and channel_dispatch under a clock_gettime deadline, as
 * fidl_bsd_sync_wait does) or through channel_call(3).  Prints the wall time
 * per call.  Run under ktrace -t c to count system calls per call:
 *
 *	ktrace -t c call_bench call 200 && kdump | awk '$3 == "CALL"' | wc -l
 */

#include <sys/types.h>
#include <sys/wait.h>

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <channel.h>

static void
die(const char *what)
{
	fprintf(stderr, "call_bench: %s: %s\n", what, strerror(errno));
	exit(1);
}

static void
echo_request(struct channel *channel, struct channel_message *request,
    void *argument)
{
	struct channel_outgoing out = CHANNEL_OUTGOING_INITIALIZER(
	    channel_message_data(request), channel_message_length(request));

	(void)channel;
	(void)argument;
	if (channel_send_reply(request, &out) != 0)
		die("reply");
	channel_message_free(request);
}

static void
serve(int fd)
{
	struct channel_options options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_PROVIDER);
	struct channel *provider;

	if (channel_create(fd, &options, &provider) != 0)
		die("provider");
	channel_set_request_handler(provider, echo_request, NULL);
	for (;;) {
		if (channel_wait(provider, channel_wants_write(provider), 1000)
		    == -1 && errno != EINTR)
			break;
		if (channel_dispatch(provider) == -1 ||
		    channel_flush(provider) == -1)
			break;
	}
	_exit(0);
}

struct split_state {
	bool done;
	int error;
};

static void
split_reply(struct channel_request *request, struct channel_message *reply,
    int error, void *argument)
{
	struct split_state *state = argument;

	state->done = true;
	state->error = error;
	channel_message_free(reply);
	channel_request_release(request);
}

/* The sequence fidl_bsd_sync_deadline()/fidl_bsd_sync_wait() performs. */
static void
split_call(struct channel *client, const struct channel_outgoing *out)
{
	struct split_state state = { false, 0 };
	struct channel_request *request;
	struct timespec deadline, now;
	int64_t ms;

	if (clock_gettime(CLOCK_MONOTONIC, &deadline) == -1)
		die("clock");
	deadline.tv_sec += 5;
	if (channel_send_request(client, out, split_reply, &state, &request)
	    != 0)
		die("send");
	while (!state.done) {
		if (clock_gettime(CLOCK_MONOTONIC, &now) == -1)
			die("clock");
		ms = (deadline.tv_sec - now.tv_sec) * 1000 +
		    (deadline.tv_nsec - now.tv_nsec) / 1000000;
		if (ms <= 0) {
			errno = ETIMEDOUT;
			die("wait");
		}
		if (channel_wait(client, channel_wants_write(client), (int)ms)
		    == -1 && errno != EINTR)
			die("wait");
		if (channel_dispatch(client) == -1)
			die("dispatch");
		if (channel_wants_write(client) && channel_flush(client) == -1)
			die("flush");
	}
	if (state.error != 0) {
		errno = state.error;
		die("reply");
	}
}

int
main(int argc, char **argv)
{
	struct channel_options options = CHANNEL_OPTIONS_INITIALIZER(
	    CHANNEL_ROLE_CLIENT);
	struct channel *client;
	struct channel_message *reply;
	struct timespec start, end;
	char *payload;
	size_t length;
	unsigned long calls, i;
	pid_t child;
	int ends[2];
	bool use_call;

	if (argc < 3 || argc > 4 ||
	    (strcmp(argv[1], "split") != 0 && strcmp(argv[1], "call") != 0)) {
		fprintf(stderr, "usage: call_bench split|call CALLS [PAYLOAD]\n");
		return (2);
	}
	use_call = strcmp(argv[1], "call") == 0;
	calls = strtoul(argv[2], NULL, 10);
	length = argc == 4 ? strtoul(argv[3], NULL, 10) : 64;
	if (length == 0 || length > 14336)
		length = 64;
	payload = malloc(length);
	if (payload == NULL)
		die("malloc");
	memset(payload, 'x', length);
	if (mac_capability_channel_create(ends) != 0)
		die("channel pair");
	child = fork();
	if (child == -1)
		die("fork");
	if (child == 0) {
		close(ends[0]);
		serve(ends[1]);
	}
	close(ends[1]);
	if (channel_create(ends[0], &options, &client) != 0)
		die("client");
	struct channel_outgoing out = CHANNEL_OUTGOING_INITIALIZER(payload,
	    length);
	/* Warm up: the first call probes kernel support and sizes blocks. */
	if (use_call) {
		if (channel_call(client, &out, &reply, 5000) != 0)
			die("call");
		channel_message_free(reply);
	} else
		split_call(client, &out);
	if (clock_gettime(CLOCK_MONOTONIC, &start) == -1)
		die("clock");
	for (i = 0; i < calls; i++) {
		if (use_call) {
			if (channel_call(client, &out, &reply, 5000) != 0)
				die("call");
			if (channel_message_length(reply) != length)
				die("reply length");
			channel_message_free(reply);
		} else
			split_call(client, &out);
	}
	if (clock_gettime(CLOCK_MONOTONIC, &end) == -1)
		die("clock");
	printf("call_bench mode=%s calls=%lu payload=%zu us_per_call=%.2f\n",
	    argv[1], calls, length,
	    ((end.tv_sec - start.tv_sec) * 1e6 +
	    (end.tv_nsec - start.tv_nsec) / 1e3) / (double)(calls ? calls : 1));
	channel_destroy(client);
	kill(child, SIGKILL);
	waitpid(child, NULL, 0);
	return (0);
}
