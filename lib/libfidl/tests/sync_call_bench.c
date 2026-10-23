/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * sync_call_bench wait|call CALLS
 *
 * CALLS synchronous Service.RoundTrip calls from the generated C bindings
 * against a forked C server, either as fidl_bsd_sync_deadline() plus
 * fidl_bsd_sync_wait_txid() around the asynchronous call ("wait", the
 * pattern the provider tests use) or through fidl_bsd_connection_call()
 * ("call").  Prints the wall time per call; run under ktrace -t c to count
 * system calls per call.  Installed for in-VM use (not a Kyua test).
 */
#include <sys/wait.h>

#include <errno.h>
#include <fidl/bsd.runtime.test/c/bsd.h>
#include <fidl/bsd/runtime_c.h>
#include <fidl/bsd/sync_c.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <channel.h>

static void
die(const char *what, int error)
{
	fprintf(stderr, "sync_call_bench: %s: %s\n", what, strerror(error));
	exit(1);
}
static void
echo(void *context, struct fidl_bsd_connection *connection,
    struct fidl_bsd_request *request, struct bsd_runtime_test_Request *value)
{
	(void)context;
	struct bsd_runtime_test_Response r = { value->text, value->text_size };
	if (bsd_runtime_test_Service_RoundTrip_reply(connection, request, &r)
	    != 0)
		_exit(10);
}
static void
serve(int fd)
{
	struct fidl_bsd_connection *server;
	if (fidl_bsd_connection_create(fd, FIDL_BSD_SERVER, &server) != 0)
		_exit(11);
	struct bsd_runtime_test_Service_server handlers = { echo, NULL, NULL };
	if (bsd_runtime_test_Service_bind(server, &handlers, NULL) != 0)
		_exit(12);
	while (fidl_bsd_connection_poll(server, 1000) == 0)
		;
	_exit(0);
}
struct call {
	struct fidl_bsd_connection *client;
	struct bsd_runtime_test_Request request;
	bool done;
	int error;
	uint32_t txid;
};
static void
response(void *context, int error, struct bsd_runtime_test_Response *value)
{
	struct call *c = context;
	c->done = true;
	c->error = error;
	if (error == 0 && (value == NULL || value->text_size != 64))
		c->error = EPROTO;
}
static int
issue(void *context)
{
	struct call *c = context;
	return bsd_runtime_test_Service_RoundTrip(c->client, &c->request,
	    response, c, &c->txid);
}
int
main(int argc, char **argv)
{
	if (argc != 3 ||
	    (strcmp(argv[1], "wait") != 0 && strcmp(argv[1], "call") != 0)) {
		fprintf(stderr, "usage: sync_call_bench wait|call CALLS\n");
		return 2;
	}
	bool use_call = strcmp(argv[1], "call") == 0;
	unsigned long calls = strtoul(argv[2], NULL, 10);
	char text[64];
	memset(text, 'x', sizeof(text));
	int ends[2];
	if (mac_capability_channel_create(ends) != 0)
		die("channel pair", errno);
	pid_t child = fork();
	if (child == -1)
		die("fork", errno);
	if (child == 0) {
		close(ends[0]);
		serve(ends[1]);
	}
	close(ends[1]);
	struct call c = { .request = { text, sizeof(text) } };
	int error = fidl_bsd_connection_create(ends[0], FIDL_BSD_CLIENT,
	    &c.client);
	if (error)
		die("client", error);
	struct timespec start, end, deadline;
	for (unsigned long i = 0; i <= calls; i++) {
		if (i == 1 && clock_gettime(CLOCK_MONOTONIC, &start) == -1)
			die("clock", errno);
		c.done = false;
		if (use_call) {
			error = fidl_bsd_connection_call(c.client, 5000, issue,
			    &c);
		} else {
			error = fidl_bsd_sync_deadline(&deadline, 5000);
			if (error == 0)
				error = issue(&c);
			if (error == 0)
				error = fidl_bsd_sync_wait_txid(c.client,
				    &c.done, &deadline, c.txid);
		}
		if (error == 0)
			error = c.error;
		if (error)
			die("round trip", error);
	}
	if (clock_gettime(CLOCK_MONOTONIC, &end) == -1)
		die("clock", errno);
	printf("sync_call_bench mode=%s calls=%lu us_per_call=%.2f\n", argv[1],
	    calls,
	    ((end.tv_sec - start.tv_sec) * 1e6 +
	    (end.tv_nsec - start.tv_nsec) / 1e3) / (double)(calls ? calls : 1));
	fidl_bsd_connection_destroy(c.client);
	kill(child, SIGKILL);
	waitpid(child, NULL, 0);
	return 0;
}
