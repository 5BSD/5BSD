/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * latency_bench [N]: N notify_stats() round trips (STATS, now GetStats) from
 * libnotify to the BSDNotify router serving one session over a capability
 * channel (see tools/build/fuchsia/daemon_bench.h).  The server child runs
 * the router's own session code on an in-process router; NOTIFY_BENCH_LEGACY
 * selects the event loop of the pre-FIDL router, whose session handling was
 * inline in router_main().  Built in the tree against the current sources,
 * and by build-daemon-bench.sh against the pre-FIDL sources.
 */
#include "daemon_bench.h"

#ifndef NOTIFY_CLIENT_SOURCE
#define NOTIFY_CLIENT_SOURCE "../../../lib/libnotify/notify.c"
#endif
#define service_open daemon_bench_service_open
#include NOTIFY_CLIENT_SOURCE
#undef service_open

/* The router side, built from bsdnotify.c in latency_bench_server.c. */
int notify_bench_serve(int);

static struct notify_client *client;

static int
serve(int fd)
{

	return (notify_bench_serve(fd));
}

static void
stats(void)
{
	struct notify_stats value;

	if (notify_stats(client, &value) == -1)
		err(1, "stats");
}

int
main(int argc, char **argv)
{
	long calls = argc > 1 ? strtol(argv[1], NULL, 10) : 2000;
	pid_t server = daemon_bench_start(serve);

	if (notify_client_open(&client) == -1)
		err(1, "open");
	daemon_bench_run("system.Notify", "GetStats", DAEMON_BENCH_VARIANT,
	    calls, stats);
	notify_client_close(client);
	daemon_bench_stop(server);
	return (0);
}
