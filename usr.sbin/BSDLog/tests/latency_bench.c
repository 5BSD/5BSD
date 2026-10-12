/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * latency_bench [N]: N statistics round trips (STATS, now GetStats) from the
 * liblogcmp process client to BSDLog's real session code over a capability
 * channel (see tools/build/fuchsia/daemon_bench.h), with an in-memory
 * backend.  Built in the tree against the current sources, and by
 * build-daemon-bench.sh against the pre-FIDL sources.  The provider's
 * logcmp.c is built separately; this file includes the client's source of
 * the same name.
 */
#include "daemon_bench.h"

#ifndef LOGCMP_CLIENT_SOURCE
#define LOGCMP_CLIENT_SOURCE "../../../lib/liblogcmp/logcmp.c"
#endif
#define service_open daemon_bench_service_open
#include LOGCMP_CLIENT_SOURCE
#undef service_open

#include "logcmp_test.h"

static struct logcmp_client *client;

static int
serve(int fd)
{

	return (logcmp_test_serve(fd, "org.5bsd.bench", 64U * 1024, 0));
}

static void
stats(void)
{
	struct logcmp_stats value;

	if (logcmp_stats(client, &value) == -1)
		err(1, "stats");
}

int
main(int argc, char **argv)
{
	long calls = argc > 1 ? strtol(argv[1], NULL, 10) : 2000;
	pid_t server = daemon_bench_start(serve);

	if (logcmp_client_open(&client) == -1)
		err(1, "open");
	daemon_bench_run("system.Log", "GetStats", DAEMON_BENCH_VARIANT, calls,
	    stats);
	logcmp_client_close(client);
	daemon_bench_stop(server);
	return (0);
}
