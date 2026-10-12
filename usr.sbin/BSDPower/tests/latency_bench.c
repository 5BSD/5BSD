/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * latency_bench [N]: N States round trips from libpowercmp to BSDPower's real
 * per-session server over a capability channel (see
 * tools/build/fuchsia/daemon_bench.h).  Built in the tree against the current
 * sources, and by build-daemon-bench.sh against the pre-FIDL sources.
 */
#include "daemon_bench.h"

#define service_open daemon_bench_service_open
#include "powercmp.c"
#undef service_open

#include "config.h"
#include "BSDPower_test.h"

static struct powercmp_client *client;

static int
serve(int fd)
{
	struct powercmp_config config;

	powercmp_config_defaults(&config);
	bsdpower_test_set_acpi_fd(-1);
	bsdpower_test_set_states(1u << 3 | 1u << 5);
	return (bsdpower_test_serve_session(fd, "org.5bsd.bench", &config));
}

static void
states(void)
{
	uint32_t supported;

	if (powercmp_states(client, &supported) == -1)
		err(1, "states");
}

int
main(int argc, char **argv)
{
	long calls = argc > 1 ? strtol(argv[1], NULL, 10) : 2000;
	pid_t server = daemon_bench_start(serve);

	if (powercmp_client_open(&client) == -1)
		err(1, "open");
	daemon_bench_run("system.Power", "States", DAEMON_BENCH_VARIANT, calls,
	    states);
	powercmp_client_close(client);
	daemon_bench_stop(server);
	return (0);
}
