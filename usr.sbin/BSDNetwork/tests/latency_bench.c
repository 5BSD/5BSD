/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * latency_bench [N]: N limit queries (HELLO, now GetLimits) from the shared
 * libnetworkcmp process client to BSDNetwork's real per-session worker over
 * a capability channel (see tools/build/fuchsia/daemon_bench.h), with the
 * default policy and no audit or log clients.  Built in the tree against the
 * current sources, and by build-daemon-bench.sh against the pre-FIDL sources.
 * The provider's networkcmp.c is built separately; this file includes the
 * client's source of the same name.
 */
#include "daemon_bench.h"

#ifndef NETWORKCMP_CLIENT_SOURCE
#define NETWORKCMP_CLIENT_SOURCE "../../../lib/libnetworkcmp/networkcmp.c"
#endif
#define service_open daemon_bench_service_open
#include NETWORKCMP_CLIENT_SOURCE
#undef service_open

#include "config.h"
#include "networkcmp_test.h"
#include "policy.h"

static struct networkcmp_client *client;

static int
serve(int fd)
{
	struct networkcmp_policy policy;

	if (networkcmp_policy_default(&policy) == -1)
		return (1);
	return (networkcmp_test_serve(fd, &policy, "org.5bsd.bench"));
}

static void
hello(void)
{
	struct networkcmp_hello_reply limits;

	if (networkcmp_hello(client, &limits) == -1)
		err(1, "hello");
}

int
main(int argc, char **argv)
{
	long calls = argc > 1 ? strtol(argv[1], NULL, 10) : 2000;
	pid_t server = daemon_bench_start(serve);

	if (networkcmp_client_open(&client) == -1)
		err(1, "open");
	daemon_bench_run("system.Network", "GetLimits", DAEMON_BENCH_VARIANT,
	    calls, hello);
	networkcmp_client_close(client);
	daemon_bench_stop(server);
	return (0);
}
